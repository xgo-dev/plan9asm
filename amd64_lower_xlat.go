package plan9asm

import "fmt"

func (c *amd64Ctx) lowerXLAT(op Op, ins Instr) (ok bool, terminated bool, err error) {
	known, err := x86XLATProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	addressType := I64
	if c.goarch == "386" {
		addressType = I32
	}
	base, err := c.evalIntSized(Operand{Kind: OpReg, Reg: BX}, addressType)
	if err != nil {
		return true, false, err
	}
	index, err := c.evalIntSized(Operand{Kind: OpReg, Reg: AL}, I8)
	if err != nil {
		return true, false, err
	}
	wideIndex, address := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i8 %s to %s\n", wideIndex, index, addressType)
	fmt.Fprintf(c.b, "  %%%s = add %s %s, %%%s\n", address, addressType, base, wideIndex)
	addressValue := "%" + address
	if addressType == I32 {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", wide, addressValue)
		addressValue = "%" + wide
	}
	pointer := c.ptrFromAddrI64(addressValue)
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load volatile i8, ptr %s, align 1\n", value, pointer)
	return true, false, c.storeRegSized(AL, I8, "%"+value)
}
