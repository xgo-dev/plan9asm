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

// lowerPackedMoveMask implements Go 1.27's complete packed move-mask family:
// PMOVMSKB, VPMOVMSKB, MOVMSKPS/PD, and VMOVMSKPS/PD. None of their tables
// contains EVEX, mask-register, suffix, or memory-source forms.
func (c *amd64Ctx) lowerPackedMoveMask(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64MoveMaskSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	vector := spec.vector
	floatingLaneBits := spec.floatingLaneBits
	if rawOp != baseOp {
		return true, false, fmt.Errorf("amd64 %s has no instruction suffixes in Go 1.27's optab: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s expects vector-or-MMX source and GP destination: %q", baseOp, ins.Raw)
	}
	if !isX86YrlRegisterForArch(ins.Args[1].Reg, c.goarch) {
		return true, false, fmt.Errorf("amd64 %s destination is outside Go 1.27's Yrl class: %q", baseOp, ins.Raw)
	}

	if floatingLaneBits != 0 {
		byteWidth := 0
		if xIndex, x := amd64ParseXReg(ins.Args[0].Reg); x {
			limit := 15
			if !vector && c.goarch == "386" {
				limit = 7
			}
			if xIndex > limit {
				return true, false, fmt.Errorf("amd64 %s source is outside its Go 1.27 register class: %q", baseOp, ins.Raw)
			}
			byteWidth = 16
		} else if yIndex, y := amd64ParseYReg(ins.Args[0].Reg); vector && y && yIndex <= 15 {
			byteWidth = 32
		} else {
			return true, false, fmt.Errorf("amd64 %s source is outside its Go 1.27 table: %q", baseOp, ins.Raw)
		}
		value, err := c.loadPackedCompareBytes(ins.Args[0], byteWidth)
		if err != nil {
			return true, false, err
		}
		mask32 := c.floatingMoveMask(value, byteWidth, floatingLaneBits)
		return true, false, c.storeRegSized(ins.Args[1].Reg, I32, mask32)
	}

	var mask32 string
	if xIndex, x := amd64ParseXReg(ins.Args[0].Reg); x && xIndex <= 15 {
		value, err := c.loadX(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		mask := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.x86.sse2.pmovmskb.128(<16 x i8> %s)\n", mask, value)
		mask32 = "%" + mask
	} else if yIndex, y := amd64ParseYReg(ins.Args[0].Reg); vector && y && yIndex <= 15 {
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
	} else if _, mmx := amd64ParseMReg(ins.Args[0].Reg); !vector && mmx {
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
	} else {
		return true, false, fmt.Errorf("amd64 %s source is outside its Go 1.27 table: %q", baseOp, ins.Raw)
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
