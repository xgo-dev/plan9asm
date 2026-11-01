package plan9asm

import (
	"fmt"
	"strings"
)

type amd64MoveMaskSpec struct {
	opcode           int
	prefix           int
	vector           bool
	floatingLaneBits int
}

// The legacy and VEX spellings share the Go table's register-to-GP shape.
// The raw decoder uses the VEX entries; x/arch handles legacy raw bytes.
var amd64MoveMaskSpecs = map[Op]amd64MoveMaskSpec{
	"PMOVMSKB":  {opcode: 0xd7, prefix: 1},
	"VPMOVMSKB": {opcode: 0xd7, prefix: 1, vector: true},
	"MOVMSKPS":  {opcode: 0x50, floatingLaneBits: 32},
	"MOVMSKPD":  {opcode: 0x50, prefix: 1, floatingLaneBits: 64},
	"VMOVMSKPS": {opcode: 0x50, vector: true, floatingLaneBits: 32},
	"VMOVMSKPD": {opcode: 0x50, prefix: 1, vector: true, floatingLaneBits: 64},
}

type x86MoveMaskForm struct {
	amd64MoveMaskSpec
	byteWidth int
}

// Shape is shared by lowering and result definedness. Acceptance supplies no
// initialized vector, MMX state, physical mode32 bank or caller permission.
func x86MoveMaskProperties(op Op, ins Instr, arch string) (x86MoveMaskForm, bool, error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64MoveMaskSpecs[Op(baseOp)]
	form := x86MoveMaskForm{amd64MoveMaskSpec: spec}
	if !recognized {
		return form, false, nil
	}
	if arch != "amd64" && arch != "386" || rawOp != baseOp ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), baseOp) {
		return form, true, fmt.Errorf("%s %s has an unbound mode, dispatch or suffix: %q", arch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
		return form, true, fmt.Errorf("%s %s expects vector-or-MMX source and GP destination: %q", arch, baseOp, ins.Raw)
	}
	if !isX86YrlRegisterForArch(ins.Args[1].Reg, arch) {
		return form, true, fmt.Errorf("%s %s destination is outside Go's Yrl class: %q", arch, baseOp, ins.Raw)
	}
	limit := 15
	if !spec.vector && arch == "386" {
		limit = 7
	}
	if index, valid := amd64ParseXReg(ins.Args[0].Reg); valid && index <= limit {
		form.byteWidth = 16
	} else if index, valid := amd64ParseYReg(ins.Args[0].Reg); spec.vector && valid && index <= 15 {
		form.byteWidth = 32
	} else if _, valid := amd64ParseMReg(ins.Args[0].Reg); !spec.vector && spec.floatingLaneBits == 0 && valid {
		form.byteWidth = 8
	} else {
		return form, true, fmt.Errorf("%s %s source is outside its Go table: %q", arch, baseOp, ins.Raw)
	}
	return form, true, nil
}

// No Go move-mask row accepts EVEX, mask-register, suffix or memory forms.
func (c *amd64Ctx) lowerPackedMoveMask(op Op, ins Instr) (ok bool, terminated bool, err error) {
	arch := c.goarch
	if arch == "" {
		arch = "amd64"
	}
	form, known, err := x86MoveMaskProperties(op, ins, arch)
	if !known || err != nil {
		return known, false, err
	}
	if form.floatingLaneBits != 0 {
		value, err := c.loadPackedCompareBytes(ins.Args[0], form.byteWidth)
		if err != nil {
			return true, false, err
		}
		mask32 := c.floatingMoveMask(value, form.byteWidth, form.floatingLaneBits)
		return true, false, c.storeRegSized(ins.Args[1].Reg, I32, mask32)
	}

	var mask32 string
	if form.byteWidth == 16 {
		value, err := c.loadX(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		mask := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.x86.sse2.pmovmskb.128(<16 x i8> %s)\n", mask, value)
		mask32 = "%" + mask
	} else if form.byteWidth == 32 {
		value, err := c.loadY(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		low := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <32 x i8> %s, <32 x i8> zeroinitializer, <16 x i32> %s\n", low, value, llvmI32RangeMask(0, 16))
		high := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <32 x i8> %s, <32 x i8> zeroinitializer, <16 x i32> %s\n", high, value, llvmI32RangeMask(16, 16))
		lowMask := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.x86.sse2.pmovmskb.128(<16 x i8> %%%s)\n", lowMask, low)
		highMask := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.x86.sse2.pmovmskb.128(<16 x i8> %%%s)\n", highMask, high)
		shifted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl i32 %%%s, 16\n", shifted, highMask)
		combined := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i32 %%%s, %%%s\n", combined, shifted, lowMask)
		mask32 = "%" + combined
	} else {
		value, err := c.loadReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		bytes := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to <8 x i8>\n", bytes, value)
		signBits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp slt <8 x i8> %%%s, zeroinitializer\n", signBits, bytes)
		mask8 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <8 x i1> %%%s to i8\n", mask8, signBits)
		widened := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i32\n", widened, mask8)
		mask32 = "%" + widened
	}

	return true, false, c.storeRegSized(ins.Args[1].Reg, I32, mask32)
}

func (c *amd64Ctx) floatingMoveMask(value string, byteWidth, laneBits int) string {
	lanes := byteWidth * 8 / laneBits
	integerLanes := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, value)
	mask := "0"
	for lane := 0; lane < lanes; lane++ {
		laneValue := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %d\n", laneValue, lanes, laneBits, integerLanes, lane)
		sign := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp slt i%d %%%s, 0\n", sign, laneBits, laneValue)
		bit := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i1 %%%s to i32\n", bit, sign)
		positioned := "%" + bit
		if lane != 0 {
			shifted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shl i32 %%%s, %d\n", shifted, bit, lane)
			positioned = "%" + shifted
		}
		combined := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i32 %s, %s\n", combined, mask, positioned)
		mask = "%" + combined
	}
	return mask
}

func isX86YrlRegisterForArch(r Reg, goarch string) bool {
	if !isAMD64YrlRegister(r) {
		return false
	}
	if goarch != "386" {
		return true
	}
	switch r {
	case AX, BX, CX, DX, SP, BP, SI, DI:
		return true
	default:
		return false
	}
}
