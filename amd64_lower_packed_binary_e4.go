package plan9asm

import "fmt"

// emitPackedBinaryE4 shares the lane pipeline after the family's grammar and
// storage checks. Legacy memory keeps its original SSE opcode and alignment
// faults. VEX/EVEX uses E4 reads: even dead outputs retain active volatile
// accesses, while inactive lanes are suppressed. The operation callback owns
// only register arithmetic; this helper supplies no source or memory authority.
func (c *amd64Ctx) emitPackedBinaryE4(ins Instr, form x86PackedBinaryForm, bits int,
	legacyMnemonic string, operation func(lanes, bits int, first, second string) string) error {
	lanes := form.byteWidth * 8 / bits
	second, err := c.loadPackedCompareLanes(ins.Args[form.second], form.byteWidth, bits, false)
	if err != nil {
		return err
	}
	var mask, value string
	if form.mask >= 0 {
		mask, err = c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return err
		}
	}
	first := ins.Args[form.first]
	if form.legacy && form.memory >= 0 {
		value, err = c.emitPackedBinaryNativeMemory(first, bits, second, legacyMnemonic)
	} else {
		var input string
		input, err = c.loadX86PackedShiftLanes(first, form.byteWidth, bits, form.broadcast, mask)
		if err == nil {
			value = operation(lanes, bits, input, second)
		}
	}
	if err != nil {
		return err
	}
	destination := ins.Args[form.destination]
	if form.mask >= 0 {
		old := "zeroinitializer"
		if !form.zeroing {
			old, err = c.loadPackedCompareLanes(destination, form.byteWidth, bits, false)
			if err != nil {
				return err
			}
		}
		value = amd64ApplyIntegerLaneMask(c, lanes, bits, value, old, mask, form.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, bits, value, form.byteWidth)
	if form.legacy {
		return c.storeLegacyPackedLogical(destination, "%"+out)
	}
	return c.storePackedMoveOperand(destination, form.byteWidth, "%"+out)
}
