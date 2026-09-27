package plan9asm

import (
	"fmt"
	"strings"
)

var amd64Shuffle128BitBlockLaneBits = map[string]int{
	"VSHUFF32X4": 32,
	"VSHUFI32X4": 32,
	"VSHUFF64X2": 64,
	"VSHUFI64X2": 64,
}

// lowerShuffle128BitBlocks implements the complete Go 1.27 _yvshuff32x4
// table. Floating and integer spellings have identical bit-level behavior.
func (c *amd64Ctx) lowerShuffle128BitBlocks(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	laneBits, ok := amd64Shuffle128BitBlockLaneBits[baseOp]
	if !ok {
		return false, false, nil
	}
	suffixes, err := amd64ParseTwoSourcePermuteSuffixes(rawOp, baseOp)
	if err != nil {
		return true, false, fmt.Errorf("%w: %q", err, ins.Raw)
	}
	if len(ins.Args) != 4 && len(ins.Args) != 5 {
		return true, false, fmt.Errorf("amd64 %s expects $imm8, first source, second source, [K mask,] destination: %q", baseOp, ins.Raw)
	}
	if ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" || ins.Args[0].Imm < 0 || ins.Args[0].Imm > 255 {
		return true, false, fmt.Errorf("amd64 %s expects an unsigned-byte immediate: %q", baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 5
	if masked && c.goarch == "386" {
		return true, false, fmt.Errorf("386 %s masked form exceeds the Go assembler frontend's operand limit: %q", baseOp, ins.Raw)
	}
	if suffixes.zeroing && !masked {
		return true, false, fmt.Errorf("amd64 %s .Z requires a K1-K7 mask: %q", baseOp, ins.Raw)
	}

	destination := ins.Args[len(ins.Args)-1]
	byteWidth := 0
	if destination.Kind == OpReg {
		byteWidth = amd64VectorByteWidth(destination.Reg)
	}
	if byteWidth != 32 && byteWidth != 64 || !c.isGoPackedVectorMoveRegister(destination, byteWidth) {
		return true, false, fmt.Errorf("amd64 %s expects an in-range Y or Z destination: %q", baseOp, ins.Raw)
	}
	second := ins.Args[2]
	if !c.isGoPackedVectorMoveRegister(second, byteWidth) {
		return true, false, fmt.Errorf("amd64 %s second source must match the destination width: %q", baseOp, ins.Raw)
	}
	first := ins.Args[1]
	if first.Kind == OpReg {
		if !c.isGoPackedVectorMoveRegister(first, byteWidth) {
			return true, false, fmt.Errorf("amd64 %s first source register must match the destination width: %q", baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(first) {
		return true, false, fmt.Errorf("amd64 %s first source must be a matching vector register or memory: %q", baseOp, ins.Raw)
	}
	if suffixes.broadcast && !isAMD64MemoryOperand(first) {
		return true, false, fmt.Errorf("amd64 %s.BCST requires a memory first source: %q", baseOp, ins.Raw)
	}

	mask := ""
	if masked {
		maskArg := ins.Args[3]
		if maskArg.Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
		maskIndex, validMask := amd64ParseKReg(maskArg.Reg)
		if !validMask || maskIndex == 0 {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
		mask, err = c.loadK(maskArg.Reg)
		if err != nil {
			return true, false, err
		}
	}

	firstValue, err := c.loadPackedCompareLanes(first, byteWidth, laneBits, suffixes.broadcast)
	if err != nil {
		return true, false, err
	}
	secondValue, err := c.loadPackedCompareLanes(second, byteWidth, laneBits, false)
	if err != nil {
		return true, false, err
	}
	lanes := byteWidth * 8 / laneBits
	computed := c.emitShuffle128BitBlocks(lanes, laneBits, firstValue, secondValue, uint8(ins.Args[0].Imm))
	if masked {
		oldBytes, err := c.loadPackedCompareBytes(destination, byteWidth)
		if err != nil {
			return true, false, err
		}
		old := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, oldBytes)
		computed = amd64ApplyIntegerLaneMask(c, lanes, laneBits, computed, old, mask, suffixes.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, laneBits, computed, byteWidth)
	return true, false, c.storeVectorBytes(destination.Reg, byteWidth, "%"+out)
}

func (c *amd64Ctx) emitShuffle128BitBlocks(lanes, laneBits int, firstPlan9, secondPlan9 string, immediate uint8) string {
	blockLanes := 128 / laneBits
	blocks := lanes / blockLanes
	indices := make([]string, 0, lanes)
	for outputBlock := 0; outputBlock < blocks; outputBlock++ {
		var sourceBlock int
		secondOperandOffset := 0
		if blocks == 2 {
			sourceBlock = int(immediate>>outputBlock) & 1
			if outputBlock == 1 {
				secondOperandOffset = lanes
			}
		} else {
			sourceBlock = int(immediate>>(2*outputBlock)) & 3
			if outputBlock >= 2 {
				secondOperandOffset = lanes
			}
		}
		for lane := 0; lane < blockLanes; lane++ {
			indices = append(indices, fmt.Sprintf("i32 %d", secondOperandOffset+sourceBlock*blockLanes+lane))
		}
	}
	shuffled := c.newTmp()
	// The second Plan 9 source is Intel SRC1 and therefore LLVM operand 0;
	// the first Plan 9 (r/m) source is Intel SRC2 / LLVM operand 1.
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i%d> %s, <%d x i%d> %s, <%d x i32> <%s>\n",
		shuffled, lanes, laneBits, secondPlan9, lanes, laneBits, firstPlan9, lanes, strings.Join(indices, ", "))
	return "%" + shuffled
}
