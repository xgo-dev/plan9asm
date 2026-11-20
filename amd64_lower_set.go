package plan9asm

import (
	"fmt"
)

// lowerConditionalSet implements the complete Go 1.27 SETcc family. All 16
// names use yscond, whose single operand is the byte-register-or-memory Ymb
// class.
func (c *amd64Ctx) lowerConditionalSet(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, recognized, err := x86ConditionalSetProperties(op, ins, c.goarch)
	if !recognized {
		return false, false, nil
	}
	if err != nil {
		return true, false, err
	}
	condition, err := c.x86Condition(form.condition)
	if err != nil {
		return true, false, err
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i8 1, i8 0\n", value, condition)
	if err := c.storeConditionalSetByte(form.destination, "%"+value); err != nil {
		return true, false, err
	}
	return true, false, nil
}

func (c *amd64Ctx) storeConditionalSetByte(dst Operand, value string) error {
	switch dst.Kind {
	case OpReg:
		return c.storeRegSized(dst.Reg, I8, value)
	case OpMem:
		ptr, ptrType, err := c.ptrFromMem(dst.Mem)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store volatile i8 %s, %s %s, align 1\n", value, ptrType, ptr)
		return nil
	case OpSym:
		ptr, err := c.ptrFromSB(dst.Sym)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store volatile i8 %s, ptr %s, align 1\n", value, ptr)
		return nil
	case OpFP:
		return c.storeFPResult(dst.FPOffset, I8, value)
	default:
		return fmt.Errorf("expected Ymb destination, got %s", dst.String())
	}
}
