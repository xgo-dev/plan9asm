package plan9asm

import (
	"fmt"
	"strings"
)

// Complete E4NF data reads survive zero masks and dead results. The same
// validated form supplies byte effects, result dependencies and lowering.
func (c *amd64Ctx) lowerShuffle128BitBlocks(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86Shuffle128BitBlocksProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if err := c.validateConflictFunnelMemory(ins, form.x86PackedBinaryForm); err != nil {
		return true, false, err
	}
	readWidth := form.byteWidth
	if form.memory >= 0 {
		readWidth = form.memoryBytes
	}
	firstBytes, err := c.loadX86PackedShiftBytes(ins.Args[form.first], readWidth, true)
	if err != nil {
		return true, false, err
	}
	lanes := form.byteWidth * 8 / form.laneBits
	var first string
	if form.broadcast {
		scalar := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to i%d\n", scalar, readWidth, firstBytes, form.laneBits)
		first = amd64SplatInteger(c, lanes, form.laneBits, "%"+scalar)
	} else {
		first = c.bitcastVectorBytesToIntegerLanes(form.byteWidth, lanes, form.laneBits, firstBytes)
	}
	secondBytes, err := c.loadX86PackedShiftBytes(ins.Args[form.second], form.byteWidth, true)
	if err != nil {
		return true, false, err
	}
	second := c.bitcastVectorBytesToIntegerLanes(form.byteWidth, lanes, form.laneBits, secondBytes)
	result := c.emitShuffle128BitBlocks(lanes, form.laneBits, first, second, form.immediate)
	if form.mask >= 0 {
		mask, err := c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return true, false, err
		}
		old := "zeroinitializer"
		if !form.zeroing {
			old, err = c.loadPackedCompareLanes(ins.Args[form.destination], form.byteWidth, form.laneBits, false)
			if err != nil {
				return true, false, err
			}
		}
		result = amd64ApplyIntegerLaneMask(c, lanes, form.laneBits, result, old, mask, form.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, form.laneBits, result, form.byteWidth)
	return true, false, c.storePackedMoveOperand(ins.Args[form.destination], form.byteWidth, "%"+out)
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
