package plan9asm

import "fmt"

func (c *amd64Ctx) lowerXLAT(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "XLAT" {
		return false, false, nil
	}
	if len(ins.Args) != 0 {
		return true, false, fmt.Errorf("%s XLAT takes no operands: %q", c.goarch, ins.Raw)
	}
	base := ""
	if c.goarch == "386" {
		value, err := c.evalIntSized(Operand{Kind: OpReg, Reg: BX}, I32)
		if err != nil {
			return true, false, err
		}
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", wide, value)
		base = "%" + wide
	} else {
		value, err := c.loadReg(BX)
		if err != nil {
			return true, false, err
		}
		base = value
	}
	index, err := c.evalIntSized(Operand{Kind: OpReg, Reg: AL}, I8)
	if err != nil {
		return true, false, err
	}
	wideIndex := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i8 %s to i64\n", wideIndex, index)
	basePointer := c.ptrFromAddrI64(base)
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = getelementptr i8, ptr %s, i64 %%%s\n", pointer, basePointer, wideIndex)
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i8, ptr %%%s, align 1\n", value, pointer)
	return true, false, c.storeRegSized(AL, I8, "%"+value)
}
