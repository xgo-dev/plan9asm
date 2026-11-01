package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) lowerMXCSR(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if ins.Op == "" {
		ins.Op = op
	} else if !strings.EqualFold(string(ins.Op), string(op)) {
		if _, known, _ := x86MXCSRProperties(Instr{Op: op}, c.goarch); known {
			return true, false, fmt.Errorf("MXCSR helper/source identity differs: %s/%s", op, ins.Op)
		}
		return false, false, nil
	}
	write, known, err := x86MXCSRProperties(ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	baseOp := strings.ToUpper(string(op))
	if memory := ins.Args[0]; memory.Kind == OpMem && memory.Mem.Sym == "" &&
		x86OrdinaryNativeMemoryOperand(memory, c.goarch) {
		pointer, pointerType, err := c.ptrFromMem(memory.Mem)
		if err != nil {
			return true, false, err
		}
		constraint := "*m,~{memory}"
		if write {
			constraint = "=*m,~{memory}"
		}
		// One original native m32 operation retains exact access/fault and
		// legacy/VEX identity, even when no numerical result is observed.
		// MXCSR does not modify integer FLAGS, DF or any GP register.
		fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s elementtype(i32) %s)\n",
			strings.ToLower(baseOp)+" $0", constraint, pointerType, pointer)
		return true, false, nil
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

// The paired original opcode either faults or continues. This lowering-only
// consumer checks actual incoming pointer/index identity, not numerical address
// bits, pointee initializedness, bounds or a reusable caller-memory permission.
func x86LoweredNativeMXCSRStep(ins Instr, state *x86ResultState, arch string) (bool, bool) {
	write, known, err := x86MXCSRProperties(ins, arch)
	if !known || err != nil || len(ins.Args) != 1 || ins.Args[0].Kind != OpMem ||
		ins.Args[0].Mem.Sym != "" || !x86OrdinaryNativeMemoryOperand(ins.Args[0], arch) {
		return false, false
	}
	if !x86ResultNamedPredicateInstruction(ins) || ins.x86NumericalRead != nil {
		return false, true
	}
	if write {
		return x86ResultIncomingPointerAddressIdentity(ins.Args[0], state, arch), true
	}
	return x86ResultIncomingPointerReadAddressIdentity(ins.Args[0], state, arch), true
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
