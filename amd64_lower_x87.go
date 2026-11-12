package plan9asm

import (
	"fmt"
	"strings"
)

func isX87Op(op Op) bool {
	switch op {
	case "FMOVB", "FMOVBP", "FMOVD", "FMOVDP", "FMOVF", "FMOVFP",
		"FMOVL", "FMOVLP", "FMOVV", "FMOVVP", "FMOVW", "FMOVWP",
		"FMOVX", "FMOVXP", "FBLD", "FBSTP", "FXCHD",
		"FADDW", "FADDL", "FADDF", "FADDD", "FADDDP",
		"FMULW", "FMULL", "FMULF", "FMULD", "FMULDP",
		"FSUBW", "FSUBL", "FSUBF", "FSUBD", "FSUBDP",
		"FSUBRW", "FSUBRL", "FSUBRF", "FSUBRD", "FSUBRDP",
		"FDIVW", "FDIVL", "FDIVF", "FDIVD", "FDIVDP",
		"FDIVRW", "FDIVRL", "FDIVRF", "FDIVRD", "FDIVRDP",
		"FCOMD", "FCOMDP", "FCOMDPP", "FCOMF", "FCOMFP", "FCOMI", "FCOMIP",
		"FCOML", "FCOMLP", "FCOMW", "FCOMWP",
		"FUCOM", "FUCOMI", "FUCOMIP", "FUCOMP", "FUCOMPP",
		"FCMOVCC", "FCMOVCS", "FCMOVEQ", "FCMOVHI", "FCMOVLS",
		"FCMOVB", "FCMOVBE", "FCMOVNB", "FCMOVNBE", "FCMOVE", "FCMOVNE", "FCMOVNU", "FCMOVU", "FCMOVUN",
		"FSTCW", "FLDCW", "FLDENV", "FRSTOR", "FSAVE", "FSTENV", "FRNDINT",
		"F2XM1", "FABS", "FCHS", "FCLEX", "FCOS", "FDECSTP", "FINCSTP", "FINIT",
		"FTST", "FSTSW", "FLD1", "FLDL2E", "FLDL2T", "FLDLG2", "FLDLN2",
		"FLDPI", "FLDZ", "FNOP", "FPATAN", "FPREM", "FPREM1", "FPTAN", "FSCALE",
		"FSIN", "FSINCOS", "FSQRT", "FXAM", "FXTRACT", "FYL2X", "FYL2XP1":
		return true
	default:
		return false
	}
}

func (c *amd64Ctx) lowerX87(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if !isX87Op(op) {
		return false, false, nil
	}
	dispatch := ins
	if dispatch.Op == "" {
		dispatch.Op = op // Legacy direct-helper callers have no second source head.
	} else if !strings.EqualFold(string(dispatch.Op), string(op)) {
		return true, false, fmt.Errorf("%s x87 dispatch/source opcode differs: %q", c.goarch, ins.Raw)
	}
	arch := c.goarch
	if arch == "" {
		arch = "amd64" // Legacy private helpers have always used the default x86 mode.
	}
	if _, known, err := x86X87WordProperties(dispatch, arch); known && err != nil {
		return true, false, err
	}
	if _, known, err := x86X87EnvironmentReadProperties(dispatch, arch); known && err != nil {
		return true, false, err
	}
	valueForm, typedValue, formErr := x86X87ValueProperties(dispatch, arch)
	if typedValue && formErr != nil {
		return true, false, formErr
	}
	if handled, err := c.lowerX87Value(op, ins, valueForm, typedValue); handled {
		return true, false, err
	}
	switch op {
	case "FSTCW":
		if len(ins.Args) != 1 || !isX87MemoryOperand(ins.Args[0]) {
			return true, false, fmt.Errorf("386 FSTCW expects memory destination: %q", ins.Raw)
		}
		if c.useHardwareX87() {
			c.storeHardwareX87ControlWord()
		}
		cw := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i16, ptr %s\n", cw, c.x87ControlSlot)
		return true, false, c.storeX87I16(ins.Args[0], "%"+cw)

	case "FLDCW":
		if len(ins.Args) != 1 || !isX87MemoryOperand(ins.Args[0]) {
			return true, false, fmt.Errorf("386 FLDCW expects memory source: %q", ins.Raw)
		}
		cw, err := c.evalIntSized(ins.Args[0], I16)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  store i16 %s, ptr %s\n", cw, c.x87ControlSlot)
		if c.useHardwareX87() {
			c.loadHardwareX87ControlWord()
		}
		return true, false, nil

	case "FLDENV", "FRSTOR":
		if len(ins.Args) != 1 || !isX87MemoryOperand(ins.Args[0]) {
			return true, false, fmt.Errorf("386 %s expects memory source: %q", op, ins.Raw)
		}
		return true, false, c.loadX87Environment(ins.Args[0])

	case "FSAVE", "FSTENV":
		if len(ins.Args) != 1 || !isX87MemoryOperand(ins.Args[0]) {
			return true, false, fmt.Errorf("386 %s expects memory destination: %q", op, ins.Raw)
		}
		if err := c.storeX87Environment(ins.Args[0]); err != nil {
			return true, false, err
		}
		if op == "FSAVE" {
			for i := range c.x87Slot {
				c.storeX87Value(i, x87ZeroValue)
			}
			fmt.Fprintf(c.b, "  store i16 895, ptr %s\n", c.x87ControlSlot)
			fmt.Fprintf(c.b, "  store i16 0, ptr %s\n", c.x87StatusSlot)
		}
		return true, false, nil

	case "FCLEX":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 FCLEX takes no operands: %q", ins.Raw)
		}
		if c.useHardwareX87() {
			fmt.Fprintln(c.b, `  call void asm sideeffect "fnclex", "~{fpsr}"()`)
		}
		status := c.newTmp()
		conditionCodes := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i16, ptr %s\n", status, c.x87StatusSlot)
		fmt.Fprintf(c.b, "  %%%s = and i16 %%%s, 32512\n", conditionCodes, status) // Preserve TOP and C3,C2,C1,C0.
		fmt.Fprintf(c.b, "  store i16 %%%s, ptr %s\n", conditionCodes, c.x87StatusSlot)
		return true, false, nil

	case "FDECSTP", "FINCSTP":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 %s takes no operands: %q", op, ins.Raw)
		}
		c.rotateX87Values(op == "FINCSTP")
		return true, false, nil

	case "FINIT":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 FINIT takes no operands: %q", ins.Raw)
		}
		if c.useHardwareX87() {
			fmt.Fprintln(c.b, `  call void asm sideeffect "fninit", "~{st},~{st(1)},~{st(2)},~{st(3)},~{st(4)},~{st(5)},~{st(6)},~{st(7)},~{fpsr}"()`)
		}
		for i := range c.x87Slot {
			c.storeX87Value(i, x87ZeroValue)
		}
		fmt.Fprintf(c.b, "  store i16 895, ptr %s\n", c.x87ControlSlot)
		fmt.Fprintf(c.b, "  store i16 0, ptr %s\n", c.x87StatusSlot)
		return true, false, nil

	case "FNOP":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 FNOP takes no operands: %q", ins.Raw)
		}
		return true, false, nil

	case "FSTSW":
		if len(ins.Args) != 1 || !(isX87MemoryOperand(ins.Args[0]) || ins.Args[0].Kind == OpReg && ins.Args[0].Reg == AX) {
			return true, false, fmt.Errorf("386 FSTSW expects memory destination or AX: %q", ins.Raw)
		}
		status := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i16, ptr %s\n", status, c.x87StatusSlot)
		return true, false, c.storeX87I16(ins.Args[0], "%"+status)

	}
	if len(ins.Args) != 0 {
		return true, false, fmt.Errorf("386 %s takes no operands: %q", op, ins.Raw)
	}
	return true, false, fmt.Errorf("%w: %s portable binary80 provider is not implemented", ErrProbeNeedsContext, op)
}

func x87OperandReg(op Operand) (int, bool) {
	if op.Kind != OpReg {
		return 0, false
	}
	return amd64ParseX87Reg(op.Reg)
}

func isX87RegisterOperand(op Operand) bool {
	_, ok := x87OperandReg(op)
	return ok
}

func isX87F0(op Operand) bool {
	index, ok := x87OperandReg(op)
	return ok && index == 0
}

func isX87MemoryOperand(op Operand) bool {
	return isAMD64MemoryOperand(op)
}

func (c *amd64Ctx) storeX87TypedMemory(dst Operand, typ LLVMType, value string) error {
	if typ == LLVMType("float") || typ == LLVMType("double") {
		if handled, err := c.storeX87NativeFloatingMove(dst, typ, value); handled {
			return err
		}
	}
	if dst.Kind == OpFP {
		if typ == LLVMType("float") {
			return c.storeScalarFPFloat(dst.FPOffset, 32, value)
		}
		if typ == LLVMType("double") {
			return c.storeScalarFPFloat(dst.FPOffset, 64, value)
		}
		return c.storeFPResult(dst.FPOffset, typ, value)
	}
	ptr, ptrType, err := c.x87MemoryPointer(dst)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.b, "  store %s %s, %s %s, align 1\n", typ, value, ptrType, ptr)
	return nil
}

func (c *amd64Ctx) x87MemoryPointer(op Operand) (string, string, error) {
	if !isX87MemoryOperand(op) {
		return "", "", fmt.Errorf("386 x87 instruction expected memory, got %s", op.String())
	}
	ptr, ptrType, err := c.x86DescriptorMemoryPointer(op)
	if err != nil {
		return "", "", fmt.Errorf("386 x87 memory operand %s: %w", op.String(), err)
	}
	return ptr, ptrType, nil
}

func (c *amd64Ctx) loadX87Environment(src Operand) error {
	ptr, ptrType, err := c.x87MemoryPointer(src)
	if err != nil {
		return err
	}
	// The 32-bit environment is one observable 28-byte read, including the
	// fields that this software model does not interpret. Keep it exact and
	// volatile even when both captured words are dead. An aggregate-width
	// integer load avoids 28 separate IR accesses and preserves address space.
	environment := c.newTmp()
	control := c.newTmp()
	statusBits := c.newTmp()
	status := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load volatile i224, %s %s, align 1\n", environment, ptrType, ptr)
	fmt.Fprintf(c.b, "  %%%s = trunc i224 %%%s to i16\n", control, environment)
	fmt.Fprintf(c.b, "  %%%s = lshr i224 %%%s, 32\n", statusBits, environment)
	fmt.Fprintf(c.b, "  %%%s = trunc i224 %%%s to i16\n", status, statusBits)
	fmt.Fprintf(c.b, "  store i16 %%%s, ptr %s\n", control, c.x87ControlSlot)
	fmt.Fprintf(c.b, "  store i16 %%%s, ptr %s\n", status, c.x87StatusSlot)
	if c.useHardwareX87() {
		c.loadHardwareX87ControlWord()
	}
	return nil
}

func (c *amd64Ctx) storeX87Environment(dst Operand) error {
	ptr, ptrType, err := c.x87MemoryPointer(dst)
	if err != nil {
		return err
	}
	if c.useHardwareX87() {
		c.storeHardwareX87ControlWord()
	}
	control := c.newTmp()
	status := c.newTmp()
	statusPtr := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i16, ptr %s\n", control, c.x87ControlSlot)
	fmt.Fprintf(c.b, "  %%%s = load i16, ptr %s\n", status, c.x87StatusSlot)
	fmt.Fprintf(c.b, "  store i16 %%%s, %s %s, align 1\n", control, ptrType, ptr)
	fmt.Fprintf(c.b, "  %%%s = getelementptr i8, %s %s, i64 4\n", statusPtr, ptrType, ptr)
	fmt.Fprintf(c.b, "  store i16 %%%s, %s %%%s, align 1\n", status, ptrType, statusPtr)
	return nil
}

func (c *amd64Ctx) storeX87I16(dst Operand, value string) error {
	switch dst.Kind {
	case OpReg:
		return c.storeRegSized(dst.Reg, I16, value)
	case OpFP:
		return c.storeFPResult(dst.FPOffset, I16, value)
	case OpMem:
		p, ptrType, err := c.ptrFromMem(dst.Mem)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store i16 %s, %s %s, align 1\n", value, ptrType, p)
		return nil
	case OpSym:
		p, err := c.ptrFromSB(dst.Sym)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store i16 %s, ptr %s, align 1\n", value, p)
		return nil
	default:
		return fmt.Errorf("386: unsupported x87 word destination %s", dst.String())
	}
}

func (c *amd64Ctx) storeHardwareX87ControlWord() {
	fmt.Fprintf(c.b, "  call void asm sideeffect \"fnstcw $0\", \"=*m,~{dirflag},~{fpsr},~{flags}\"(ptr elementtype(i16) %s)\n", c.x87ControlSlot)
}

func (c *amd64Ctx) loadHardwareX87ControlWord() {
	fmt.Fprintf(c.b, "  call void asm sideeffect \"fldcw $0\", \"*m,~{dirflag},~{fpsr},~{flags}\"(ptr elementtype(i16) %s)\n", c.x87ControlSlot)
}
