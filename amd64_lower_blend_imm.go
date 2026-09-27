package plan9asm

import (
	"fmt"
	"strings"
)

// lowerImmediatePackedBlend implements the complete Go 1.27 immediate
// packed-blend family. The legacy instructions use yxshuf, while all four
// V-prefixed instructions use _yvblendpd and therefore have VEX X/Y forms
// only (no EVEX Z, mask, zeroing, broadcast, or SAE forms).
func (c *amd64Ctx) lowerImmediatePackedBlend(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	suffix := ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	laneBits, vector, recognized := amd64ImmediatePackedBlendProperties(baseOp)
	if !recognized {
		return false, false, nil
	}
	if suffix != "" {
		return true, false, fmt.Errorf("%s %s has a suffix absent from its Go 1.27 optab: %q", c.goarch, baseOp, ins.Raw)
	}
	if !vector {
		return c.lowerLegacyImmediatePackedBlend(baseOp, laneBits, ins)
	}
	return c.lowerVectorImmediatePackedBlend(baseOp, laneBits, ins)
}

func amd64ImmediatePackedBlendProperties(op string) (laneBits int, vector, ok bool) {
	switch op {
	case "PBLENDW":
		return 16, false, true
	case "BLENDPS":
		return 32, false, true
	case "BLENDPD":
		return 64, false, true
	case "VPBLENDW":
		return 16, true, true
	case "VPBLENDD", "VBLENDPS":
		return 32, true, true
	case "VBLENDPD":
		return 64, true, true
	default:
		return 0, false, false
	}
}

func (c *amd64Ctx) lowerLegacyImmediatePackedBlend(baseOp string, laneBits int, ins Instr) (bool, bool, error) {
	if len(ins.Args) != 3 {
		return true, false, fmt.Errorf("%s %s expects $u8, X/m128, X: %q", c.goarch, baseOp, ins.Raw)
	}
	imm, ok := amd64UnsignedImm8(ins.Args[0])
	if !ok {
		return true, false, fmt.Errorf("%s %s immediate is outside Go 1.27's unsigned-imm8 class: %q", c.goarch, baseOp, ins.Raw)
	}
	if ins.Args[2].Kind != OpReg || !c.isGoLegacyXReg(ins.Args[2].Reg) {
		return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's legacy X class: %q", c.goarch, baseOp, ins.Raw)
	}
	if ins.Args[1].Kind == OpReg {
		if !c.isGoLegacyXReg(ins.Args[1].Reg) {
			return true, false, fmt.Errorf("%s %s source is outside Go 1.27's legacy X class: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(ins.Args[1]) {
		return true, false, fmt.Errorf("%s %s source must be X or memory: %q", c.goarch, baseOp, ins.Raw)
	}
	firstBytes, err := c.loadPackedCompareBytes(ins.Args[1], 16)
	if err != nil {
		return true, false, err
	}
	secondBytes, err := c.loadX(ins.Args[2].Reg)
	if err != nil {
		return true, false, err
	}
	result := c.emitImmediatePackedBlend(16, laneBits, imm, firstBytes, secondBytes)
	return true, false, c.storeX(ins.Args[2].Reg, result)
}

func (c *amd64Ctx) lowerVectorImmediatePackedBlend(baseOp string, laneBits int, ins Instr) (bool, bool, error) {
	if c.goarch != "amd64" {
		return true, false, fmt.Errorf("386 %s exceeds the Go assembler frontend's three-operand limit: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 4 {
		return true, false, fmt.Errorf("amd64 %s expects $u8, X/Y memory-or-register, X/Y register, X/Y destination: %q", baseOp, ins.Raw)
	}
	imm, ok := amd64UnsignedImm8(ins.Args[0])
	if !ok {
		return true, false, fmt.Errorf("amd64 %s immediate is outside Go 1.27's unsigned-imm8 class: %q", baseOp, ins.Raw)
	}
	dstArg := ins.Args[3]
	if dstArg.Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s expects a vector-register destination: %q", baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(dstArg.Reg)
	if byteWidth != 16 && byteWidth != 32 {
		return true, false, fmt.Errorf("amd64 %s expects an X or Y destination: %q", baseOp, ins.Raw)
	}
	if !amd64VEXVectorRegister(dstArg, byteWidth) || !amd64VEXVectorRegister(ins.Args[2], byteWidth) {
		return true, false, fmt.Errorf("amd64 %s second source and destination must be same-width VEX X/Y registers: %q", baseOp, ins.Raw)
	}
	if ins.Args[1].Kind == OpReg {
		if !amd64VEXVectorRegister(ins.Args[1], byteWidth) {
			return true, false, fmt.Errorf("amd64 %s first source must match its destination's VEX width: %q", baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(ins.Args[1]) {
		return true, false, fmt.Errorf("amd64 %s first source must be a vector register or memory: %q", baseOp, ins.Raw)
	}
	firstBytes, err := c.loadPackedCompareBytes(ins.Args[1], byteWidth)
	if err != nil {
		return true, false, err
	}
	secondBytes, err := c.loadPackedCompareBytes(ins.Args[2], byteWidth)
	if err != nil {
		return true, false, err
	}
	result := c.emitImmediatePackedBlend(byteWidth, laneBits, imm, firstBytes, secondBytes)
	return true, false, c.storeVectorBytes(dstArg.Reg, byteWidth, result)
}

// emitImmediatePackedBlend selects the first (r/m) source when the immediate
// bit is one and the second source when it is zero. VPBLENDW repeats the eight
// immediate bits independently in each 128-bit lane of a Y register.
func (c *amd64Ctx) emitImmediatePackedBlend(byteWidth, laneBits int, imm uint8, firstBytes, secondBytes string) string {
	lanes := byteWidth * 8 / laneBits
	first := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, firstBytes)
	second := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, secondBytes)
	mask := make([]string, 0, lanes)
	for lane := 0; lane < lanes; lane++ {
		if imm&(1<<uint(lane%8)) != 0 {
			mask = append(mask, fmt.Sprintf("i32 %d", lane))
		} else {
			mask = append(mask, fmt.Sprintf("i32 %d", lanes+lane))
		}
	}
	shuffled := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i%d> %s, <%d x i%d> %s, <%d x i32> <%s>\n",
		shuffled, lanes, laneBits, first, lanes, laneBits, second, lanes, strings.Join(mask, ", "))
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %%%s to <%d x i8>\n", out, lanes, laneBits, shuffled, byteWidth)
	return "%" + out
}
