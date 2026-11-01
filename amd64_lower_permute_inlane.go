package plan9asm

import (
	"fmt"
)

// lowerInLaneFloatingPermute implements the complete Go 1.27 _yvpermilpd
// operand family shared by VPERMILPD and VPERMILPS. The permutation preserves
// element bits and never selects across a 128-bit lane.
func (c *amd64Ctx) lowerInLaneFloatingPermute(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, known, err := x86InLanePermuteProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	return c.lowerElementPermute(form, ins)
}

func (c *amd64Ctx) lowerElementPermute(form x86ElementPermuteForm, ins Instr) (bool, bool, error) {
	lanes := form.byteWidth * 8 / form.bits
	readWidth := form.byteWidth
	if form.memory >= 0 {
		readWidth = form.memoryBytes
	}
	// E4NF retains the complete source/control tuple even for a dead result,
	// an immediate selecting one lane, or a zero opmask. Share exact volatile
	// unaligned reads, not an LLVM load that optimization may discard.
	bytes, err := c.loadX86PackedShiftBytes(ins.Args[form.source], readWidth, true)
	if err != nil {
		return true, false, err
	}
	var input string
	if form.broadcast {
		scalar := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to i%d\n", scalar, readWidth, bytes, form.bits)
		input = amd64SplatInteger(c, lanes, form.bits, "%"+scalar)
	} else {
		input = c.bitcastVectorBytesToIntegerLanes(form.byteWidth, lanes, form.bits, bytes)
	}
	var result string
	if form.immediate {
		result = c.emitImmediateElementPermute(input, form)
	} else {
		dataBytes, err := c.loadPackedCompareBytes(ins.Args[form.data], form.byteWidth)
		if err != nil {
			return true, false, err
		}
		data := c.bitcastVectorBytesToIntegerLanes(form.byteWidth, lanes, form.bits, dataBytes)
		if form.wholeVector {
			// Whole-vector r/m is data, whereas VPERMIL r/m is control.
			data, input = input, data
		}
		result = c.emitVariableElementPermute(data, input, form)
	}
	if form.mask >= 0 {
		mask, err := c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return true, false, err
		}
		old := "zeroinitializer"
		if !form.zeroing {
			old, err = c.loadPackedCompareLanes(ins.Args[form.destination], form.byteWidth, form.bits, false)
			if err != nil {
				return true, false, err
			}
		}
		result = amd64ApplyIntegerLaneMask(c, lanes, form.bits, result, old, mask, form.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, form.bits, result, form.byteWidth)
	return true, false, c.storePackedMoveOperand(ins.Args[form.destination], form.byteWidth, "%"+out)
}

func (c *amd64Ctx) emitImmediateElementPermute(data string, form x86ElementPermuteForm) string {
	lanes, laneBits := form.byteWidth*8/form.bits, form.bits
	result := "poison"
	for lane := 0; lane < lanes; lane++ {
		sourceLane := form.sourceByte(lane*(laneBits/8)) / (laneBits / 8)
		value := c.newTmp()
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %d\n", value, lanes, laneBits, data, sourceLane)
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> %s, i%d %%%s, i32 %d\n", inserted, lanes, laneBits, result, laneBits, value, lane)
		result = "%" + inserted
	}
	return result
}

func (c *amd64Ctx) emitVariableElementPermute(data, control string, form x86ElementPermuteForm) string {
	lanes, laneBits := form.byteWidth*8/form.bits, form.bits
	result := "poison"
	groupLanes := 128 / laneBits
	if form.wholeVector {
		groupLanes = lanes
	}
	for lane := 0; lane < lanes; lane++ {
		controlLane := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %d\n", controlLane, lanes, laneBits, control, lane)
		selectorValue := "%" + controlLane
		if laneBits == 64 && !form.wholeVector {
			shifted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = lshr i64 %%%s, 1\n", shifted, controlLane)
			selectorValue = "%" + shifted
		}
		selector := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i%d %s, %d\n", selector, laneBits, selectorValue, groupLanes-1)
		index := "%" + selector
		groupBase := lane / groupLanes * groupLanes
		if groupBase != 0 {
			withBase := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i%d %%%s, %d\n", withBase, laneBits, selector, groupBase)
			index = "%" + withBase
		}
		value := c.newTmp()
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i%d %s\n", value, lanes, laneBits, data, laneBits, index)
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> %s, i%d %%%s, i32 %d\n", inserted, lanes, laneBits, result, laneBits, value, lane)
		result = "%" + inserted
	}
	return result
}
