package plan9asm

import (
	"fmt"
	"strings"
)

// amd64VectorAlignSpecs is the complete Go 1.27 VALIGN family. Both opcodes
// use _yvalignd; they differ only in element and broadcast width.
var amd64VectorAlignSpecs = map[Op]int{
	"VALIGND": 32,
	"VALIGNQ": 64,
}

func (c *amd64Ctx) lowerVectorAlign(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	suffix := ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	laneBits, recognized := amd64VectorAlignSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	// The 386 assembler frontend rejects the required four- and five-operand
	// spellings before reaching the shared _yvalignd table.
	if c.goarch != "amd64" {
		return true, false, fmt.Errorf("%s %s is rejected by Go 1.27's x86 assembler operand limit: %q", c.goarch, baseOp, ins.Raw)
	}

	broadcast, zeroing := false, false
	switch suffix {
	case "":
	case "Z":
		zeroing = true
	case "BCST":
		broadcast = true
	case "BCST.Z":
		broadcast, zeroing = true, true
	default:
		return true, false, fmt.Errorf("amd64 %s has a suffix absent from Go 1.27's EVEX encoding: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 4 && len(ins.Args) != 5 {
		return true, false, fmt.Errorf("amd64 %s expects unsigned-imm8, src1, src2, [K mask,] destination: %q", baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 5
	if zeroing && !masked {
		return true, false, fmt.Errorf("amd64 %s zeroing requires a K1-K7 mask: %q", baseOp, ins.Raw)
	}
	if !amd64UnsignedImmediate(ins.Args[0], 8) {
		return true, false, fmt.Errorf("amd64 %s first operand must be Go 1.27's unsigned-imm8 class: %q", baseOp, ins.Raw)
	}

	destination := ins.Args[len(ins.Args)-1]
	if destination.Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s destination must be an X, Y, or Z register: %q", baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(destination.Reg)
	if byteWidth != 16 && byteWidth != 32 && byteWidth != 64 || !amd64EVEXVectorRegister(destination, byteWidth) {
		return true, false, fmt.Errorf("amd64 %s destination is outside Go 1.27's EVEX vector class: %q", baseOp, ins.Raw)
	}
	if !amd64EVEXVectorRegister(ins.Args[2], byteWidth) {
		return true, false, fmt.Errorf("amd64 %s second source must be a same-width EVEX vector register: %q", baseOp, ins.Raw)
	}
	if broadcast {
		if !isAMD64MemoryOperand(ins.Args[1]) {
			return true, false, fmt.Errorf("amd64 %s.BCST requires a memory first source: %q", baseOp, ins.Raw)
		}
	} else if ins.Args[1].Kind == OpReg {
		if !amd64EVEXVectorRegister(ins.Args[1], byteWidth) {
			return true, false, fmt.Errorf("amd64 %s first source must match the destination width: %q", baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(ins.Args[1]) {
		return true, false, fmt.Errorf("amd64 %s first source must be a vector register or memory: %q", baseOp, ins.Raw)
	}

	mask := ""
	if masked {
		if !amd64NonzeroKOperand(ins.Args[3]) {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
		mask, err = c.loadK(ins.Args[3].Reg)
		if err != nil {
			return true, false, err
		}
	}

	lanes := byteWidth * 8 / laneBits
	var first string
	if broadcast {
		scalar, loadErr := c.evalIntSized(ins.Args[1], amd64IntegerTypeForBits(laneBits))
		if loadErr != nil {
			return true, false, loadErr
		}
		first = amd64SplatInteger(c, lanes, laneBits, scalar)
	} else {
		firstBytes, loadErr := c.loadPackedCompareBytes(ins.Args[1], byteWidth)
		if loadErr != nil {
			return true, false, loadErr
		}
		first = c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, firstBytes)
	}
	secondBytes, err := c.loadPackedCompareBytes(ins.Args[2], byteWidth)
	if err != nil {
		return true, false, err
	}
	second := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, secondBytes)
	result := c.emitVectorAlign(lanes, laneBits, first, second, uint8(ins.Args[0].Imm))
	if masked {
		oldBytes, loadErr := c.loadPackedCompareBytes(destination, byteWidth)
		if loadErr != nil {
			return true, false, loadErr
		}
		old := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, oldBytes)
		result = amd64ApplyIntegerLaneMask(c, lanes, laneBits, result, old, mask, zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, laneBits, result, byteWidth)
	return true, false, c.storeVectorBytes(destination.Reg, byteWidth, "%"+out)
}

func (c *amd64Ctx) emitVectorAlign(lanes, laneBits int, first, second string, immediate uint8) string {
	count := int(immediate) & (lanes - 1)
	indices := make([]string, lanes)
	for lane := range indices {
		indices[lane] = fmt.Sprintf("i32 %d", lane+count)
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i%d> %s, <%d x i%d> %s, <%d x i32> <%s>\n",
		result, lanes, laneBits, first, lanes, laneBits, second, lanes, strings.Join(indices, ", "))
	return "%" + result
}
