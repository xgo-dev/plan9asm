package plan9asm

import (
	"fmt"
)

type amd64MinimumPositionSpec struct {
	vector    bool
	mapNumber int
	opcode    int
}

// Both encodings have one X/m128 input, a 128-bit output and eight unsigned
// word lanes. Named lowering and raw VEX decoding share the family table.
var amd64MinimumPositionSpecs = map[Op]amd64MinimumPositionSpec{
	"PHMINPOSUW":  {mapNumber: 2, opcode: 0x41},
	"VPHMINPOSUW": {vector: true, mapNumber: 2, opcode: 0x41},
}

// lowerPackedUnsignedWordMinimumPosition implements every Go 1.27 form of
// PHMINPOSUW (yxm_q4) and VPHMINPOSUW (_yvaesimc). Both tables are restricted
// to a single X/m128 source and an X destination; the VEX spelling is also a
// two-operand, destructive-looking Plan 9 form.
func (c *amd64Ctx) lowerPackedUnsignedWordMinimumPosition(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, recognized, err := x86BlendMinposProperties(op, ins, c.goarch)
	if !recognized || !form.minimum {
		return false, false, nil
	}
	if err != nil {
		return true, false, err
	}
	if form.legacy && form.memory {
		return true, false, c.lowerLegacyBlendMinposMemory(ins, form)
	}
	bytesValue, err := c.loadX86PackedShiftBytes(ins.Args[0], 16, true)
	if err != nil {
		return true, false, err
	}
	words := c.bitcastVectorBytesToIntegerLanes(16, 8, 16, bytesValue)
	result := c.emitPackedUnsignedWordMinimumPosition(words)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <8 x i16> %s to <16 x i8>\n", out, result)
	if !form.legacy {
		return true, false, c.storePackedMoveOperand(ins.Args[1], 16, "%"+out)
	}
	return true, false, c.storeLegacyXViews(ins.Args[1].Reg, "%"+out)
}

// Legacy SSE replaces the low 128 bits in every live view without changing
// the upper bytes. A narrow store into each wider slot expresses that directly.
func (c *amd64Ctx) storeLegacyXViews(dst Reg, value string) error {
	index, valid := amd64ParseXReg(dst)
	if !valid {
		return fmt.Errorf("invalid legacy X register %s", dst)
	}
	for _, slots := range []map[int]string{c.xRegSlot, c.yRegSlot, c.zRegSlot} {
		if slot, live := slots[index]; live {
			fmt.Fprintf(c.b, "  store <16 x i8> %s, ptr %s\n", value, slot)
		}
	}
	return nil
}

func (c *amd64Ctx) emitPackedUnsignedWordMinimumPosition(words string) string {
	minimum := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement <8 x i16> %s, i32 0\n", minimum, words)
	minimumValue := "%" + minimum
	indexValue := "0"
	for lane := 1; lane < 8; lane++ {
		value := c.newTmp()
		less := c.newTmp()
		selectedMinimum := c.newTmp()
		selectedIndex := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <8 x i16> %s, i32 %d\n", value, words, lane)
		fmt.Fprintf(c.b, "  %%%s = icmp ult i16 %%%s, %s\n", less, value, minimumValue)
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i16 %%%s, i16 %s\n", selectedMinimum, less, value, minimumValue)
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i16 %d, i16 %s\n", selectedIndex, less, lane, indexValue)
		minimumValue = "%" + selectedMinimum
		indexValue = "%" + selectedIndex
	}
	withMinimum := c.newTmp()
	withIndex := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <8 x i16> zeroinitializer, i16 %s, i32 0\n", withMinimum, minimumValue)
	fmt.Fprintf(c.b, "  %%%s = insertelement <8 x i16> %%%s, i16 %s, i32 1\n", withIndex, withMinimum, indexValue)
	return "%" + withIndex
}
