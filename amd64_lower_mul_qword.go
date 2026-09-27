package plan9asm

import (
	"fmt"
	"strings"
)

// lowerPackedQwordMultiply implements every Go 1.27 VPMULLQ form from the
// shared _yvblendmpd table, including scalar broadcast and EVEX masking.
func (c *amd64Ctx) lowerPackedQwordMultiply(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	if baseOp != "VPMULLQ" {
		return false, false, nil
	}
	suffixes, err := amd64ParseTwoSourcePermuteSuffixes(rawOp, baseOp)
	if err != nil {
		return true, false, fmt.Errorf("%w: %q", err, ins.Raw)
	}
	if len(ins.Args) != 3 && len(ins.Args) != 4 {
		return true, false, fmt.Errorf("amd64 VPMULLQ expects first source, second source, [K mask,] destination: %q", ins.Raw)
	}
	masked := len(ins.Args) == 4
	if masked && c.goarch == "386" {
		return true, false, fmt.Errorf("386 VPMULLQ masked form exceeds the Go assembler frontend's operand limit: %q", ins.Raw)
	}
	if suffixes.zeroing && !masked {
		return true, false, fmt.Errorf("amd64 VPMULLQ .Z requires a K1-K7 mask: %q", ins.Raw)
	}

	destination := ins.Args[len(ins.Args)-1]
	byteWidth := 0
	if destination.Kind == OpReg {
		byteWidth = amd64VectorByteWidth(destination.Reg)
	}
	if byteWidth == 0 || !c.isGoPackedVectorMoveRegister(destination, byteWidth) {
		return true, false, fmt.Errorf("amd64 VPMULLQ expects an in-range X, Y, or Z destination: %q", ins.Raw)
	}
	second := ins.Args[1]
	if !c.isGoPackedVectorMoveRegister(second, byteWidth) {
		return true, false, fmt.Errorf("amd64 VPMULLQ second source must match the destination width: %q", ins.Raw)
	}
	first := ins.Args[0]
	if first.Kind == OpReg {
		if !c.isGoPackedVectorMoveRegister(first, byteWidth) {
			return true, false, fmt.Errorf("amd64 VPMULLQ first source register must match the destination width: %q", ins.Raw)
		}
	} else if !isAMD64MemoryOperand(first) {
		return true, false, fmt.Errorf("amd64 VPMULLQ first source must be a matching vector register or memory: %q", ins.Raw)
	}
	if suffixes.broadcast && !isAMD64MemoryOperand(first) {
		return true, false, fmt.Errorf("amd64 VPMULLQ.BCST requires a memory first source: %q", ins.Raw)
	}

	mask := ""
	if masked {
		maskArg := ins.Args[2]
		if maskArg.Kind != OpReg {
			return true, false, fmt.Errorf("amd64 VPMULLQ masked form expects K1-K7: %q", ins.Raw)
		}
		maskIndex, validMask := amd64ParseKReg(maskArg.Reg)
		if !validMask || maskIndex == 0 {
			return true, false, fmt.Errorf("amd64 VPMULLQ masked form expects K1-K7: %q", ins.Raw)
		}
		mask, err = c.loadK(maskArg.Reg)
		if err != nil {
			return true, false, err
		}
	}

	lanes := byteWidth / 8
	firstValue, err := c.loadPackedCompareLanes(first, byteWidth, 64, suffixes.broadcast)
	if err != nil {
		return true, false, err
	}
	secondValue, err := c.loadPackedCompareLanes(second, byteWidth, 64, false)
	if err != nil {
		return true, false, err
	}
	product := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = mul <%d x i64> %s, %s\n", product, lanes, secondValue, firstValue)
	result := "%" + product
	if masked {
		oldBytes, err := c.loadPackedCompareBytes(destination, byteWidth)
		if err != nil {
			return true, false, err
		}
		old := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, 64, oldBytes)
		result = amd64ApplyIntegerLaneMask(c, lanes, 64, result, old, mask, suffixes.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i64> %s to <%d x i8>\n", out, lanes, result, byteWidth)
	return true, false, c.storeVectorBytes(destination.Reg, byteWidth, "%"+out)
}
