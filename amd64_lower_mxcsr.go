package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) lowerMXCSR(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	switch baseOp {
	case "LDMXCSR", "VLDMXCSR", "STMXCSR", "VSTMXCSR":
		// handled below
	default:
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("amd64 %s does not accept instruction suffixes: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 1 || !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("amd64 %s expects one memory operand: %q", baseOp, ins.Raw)
	}
	slot := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = alloca i32\n", slot)
	switch baseOp {
	case "LDMXCSR", "VLDMXCSR":
		value, err := c.evalIntSized(ins.Args[0], I32)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  store i32 %s, ptr %%%s\n", value, slot)
		fmt.Fprintf(c.b, "  call void @llvm.x86.sse.ldmxcsr(ptr %%%s)\n", slot)
		return true, false, nil
	case "STMXCSR", "VSTMXCSR":
		value := c.newTmp()
		fmt.Fprintf(c.b, "  call void @llvm.x86.sse.stmxcsr(ptr %%%s)\n", slot)
		fmt.Fprintf(c.b, "  %%%s = load i32, ptr %%%s\n", value, slot)
		if err := c.storeMXCSRMemory(ins.Args[0], "%"+value); err != nil {
			return true, false, err
		}
		return true, false, nil
	default:
		panic("MXCSR opcode precheck drift")
	}
}

func (c *amd64Ctx) storeMXCSRMemory(dst Operand, value string) error {
	switch dst.Kind {
	case OpMem:
		ptr, ptrType, err := c.ptrFromMem(dst.Mem)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store i32 %s, %s %s, align 1\n", value, ptrType, ptr)
		return nil
	case OpSym:
		ptr, err := c.ptrFromSB(dst.Sym)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store i32 %s, ptr %s, align 1\n", value, ptr)
		return nil
	case OpFP:
		return c.storeFPResult(dst.FPOffset, I32, value)
	default:
		return fmt.Errorf("amd64: unsupported MXCSR memory operand %s", dst.String())
	}
}
