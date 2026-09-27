package plan9asm

import (
	"fmt"
	"strings"
)

// lowerConditionalSet implements the complete Go 1.27 SETcc family. All 16
// names use yscond, whose single operand is the byte-register-or-memory Ymb
// class.
func (c *amd64Ctx) lowerConditionalSet(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	switch baseOp {
	case "SETCC", "SETCS", "SETEQ", "SETGE", "SETGT", "SETHI", "SETLE", "SETLS",
		"SETLT", "SETMI", "SETNE", "SETOC", "SETOS", "SETPC", "SETPL", "SETPS":
	default:
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("amd64 %s does not accept instruction suffixes: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 1 {
		return true, false, fmt.Errorf("amd64 %s expects one Ymb destination: %q", baseOp, ins.Raw)
	}
	dst := ins.Args[0]
	if dst.Kind == OpReg && !isGoYmbRegisterForArch(dst.Reg, c.goarch) {
		return true, false, fmt.Errorf("amd64 %s register is outside Go 1.27's Ymb class for %s: %q", baseOp, c.goarch, ins.Raw)
	}
	if dst.Kind != OpReg && !isAMD64MemoryOperand(dst) {
		return true, false, fmt.Errorf("amd64 %s expects a Ymb register or memory destination: %q", baseOp, ins.Raw)
	}
	condition, err := c.x86Condition(strings.TrimPrefix(baseOp, "SET"))
	if err != nil {
		return true, false, err
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i8 1, i8 0\n", value, condition)
	if err := c.storeConditionalSetByte(dst, "%"+value); err != nil {
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
		fmt.Fprintf(c.b, "  store i8 %s, %s %s, align 1\n", value, ptrType, ptr)
		return nil
	case OpSym:
		ptr, err := c.ptrFromSB(dst.Sym)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store i8 %s, ptr %s, align 1\n", value, ptr)
		return nil
	case OpFP:
		return c.storeFPResult(dst.FPOffset, I8, value)
	default:
		return fmt.Errorf("expected Ymb destination, got %s", dst.String())
	}
}
