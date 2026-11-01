package plan9asm

import "fmt"

// lowerAlternatingFloatingAddSubtract implements the complete Go 1.27 yxm
// and _yvaddsubpd families. Even lanes subtract the Plan 9 first source from
// the destination/base source; odd lanes add it.
func (c *amd64Ctx) lowerAlternatingFloatingAddSubtract(op Op, ins Instr) (ok bool, terminated bool, err error) {
	local := ins
	local.Op = op
	form, known, err := x86AlternatingFloatProperties(local, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if form.legacy && form.memory >= 0 && ins.Args[form.first].Kind != OpFP {
		return true, false, c.emitLegacyAlternatingRoundMemory(local, form, nil)
	}
	first, err := c.loadAlternatingRoundFloat(ins.Args[form.first], form.byteWidth, form.bits, !form.legacy)
	if err != nil {
		return true, false, err
	}
	second, err := c.loadHorizontalFloatingOperand(ins.Args[form.second], form.byteWidth, form.bits)
	if err != nil {
		return true, false, err
	}
	result := c.emitAlternatingFloatingAddSubtract(form.byteWidth, form.bits, first, second)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <%d x i8>\n", out, amd64FMA3LLVMType(form.byteWidth*8/form.bits, form.bits), result, form.byteWidth)
	if form.legacy {
		return true, false, c.storeX(ins.Args[form.destination].Reg, "%"+out)
	}
	return true, false, c.storePackedMoveOperand(ins.Args[form.destination], form.byteWidth, "%"+out)
}

func (c *amd64Ctx) emitAlternatingFloatingAddSubtract(byteWidth, laneBits int, first, second string) string {
	lanes := byteWidth * 8 / laneBits
	typeName := amd64FMA3LLVMType(lanes, laneBits)
	elementType := amd64FMA3LLVMType(1, laneBits)
	result := "poison"
	for lane := 0; lane < lanes; lane++ {
		left := c.newTmp()
		right := c.newTmp()
		value := c.newTmp()
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", left, typeName, second, lane)
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", right, typeName, first, lane)
		operation := "fsub"
		if lane%2 == 1 {
			operation = "fadd"
		}
		fmt.Fprintf(c.b, "  %%%s = %s %s %%%s, %%%s\n", value, operation, elementType, left, right)
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, %s %%%s, i32 %d\n", inserted, typeName, result, elementType, value, lane)
		result = "%" + inserted
	}
	return result
}
