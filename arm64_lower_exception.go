package plan9asm

import (
	"fmt"
	"strings"
)

type arm64ExceptionForm struct {
	mnemonic  string
	immediate uint16
}

func decodeARM64RawException(word uint32) (arm64ExceptionForm, bool) {
	switch word {
	case 0xd69f03e0:
		return arm64ExceptionForm{mnemonic: "eret"}, true
	case 0xd6bf03e0:
		return arm64ExceptionForm{mnemonic: "drps"}, true
	}
	var mnemonic string
	switch word &^ (0xffff << 5) {
	case 0xd4000002:
		mnemonic = "hvc"
	case 0xd4000003:
		mnemonic = "smc"
	case 0xd4200000:
		mnemonic = "brk"
	case 0xd4400000:
		mnemonic = "hlt"
	case 0xd4a00001:
		mnemonic = "dcps1"
	case 0xd4a00002:
		mnemonic = "dcps2"
	case 0xd4a00003:
		mnemonic = "dcps3"
	default:
		return arm64ExceptionForm{}, false
	}
	return arm64ExceptionForm{mnemonic: mnemonic, immediate: uint16(word >> 5)}, true
}

func parseARM64Exception(ins Instr) (arm64ExceptionForm, error) {
	switch op := arm64ControlOp(ins); op {
	case "ERET", "DRPS":
		if ins.Op != op || len(ins.Args) != 0 {
			return arm64ExceptionForm{}, fmt.Errorf("arm64 %s takes no operands or suffix: %q", op, ins.Raw)
		}
		return arm64ExceptionForm{mnemonic: strings.ToLower(string(op))}, nil
	case "HVC", "SMC", "HLT", "DCPS1", "DCPS2", "DCPS3", "BRK":
		if ins.Op != op || len(ins.Args) > 1 {
			return arm64ExceptionForm{}, fmt.Errorf("arm64 %s accepts no operand or one constant operand, with no suffix: %q", op, ins.Raw)
		}
		form := arm64ExceptionForm{mnemonic: strings.ToLower(string(op))}
		if len(ins.Args) == 1 {
			operand := ins.Args[0]
			if operand.Kind != OpImm || operand.ImmRaw != "" || operand.ImmIsFloat {
				return arm64ExceptionForm{}, fmt.Errorf("arm64 %s operand must be a constant: %q", op, ins.Raw)
			}
			form.immediate = uint16(operand.Imm)
		}
		return form, nil
	case OpWORD:
		if len(ins.Args) == 1 && ins.Args[0].Kind == OpImm {
			if form, ok := decodeARM64RawException(uint32(ins.Args[0].Imm)); ok {
				_, err := arm64RawWordValue(ins)
				return form, err
			}
		}
	}
	return arm64ExceptionForm{}, nil
}

func (form arm64ExceptionForm) assembly() string {
	switch form.mnemonic {
	case "eret", "drps":
		return form.mnemonic
	default:
		return fmt.Sprintf("%s #%d", form.mnemonic, form.immediate)
	}
}

func (form arm64ExceptionForm) needsPhysicalEntry() bool {
	return form.mnemonic != "" && form.mnemonic != "brk"
}

func (form arm64ExceptionForm) needsEL3() bool {
	return form.mnemonic == "smc" || form.mnemonic == "dcps3"
}

func (form arm64ExceptionForm) physicalContextError() error {
	return fmt.Errorf("%w: ARM64 %s requires a frameless physical exception sequence",
		ErrProbeNeedsContext, strings.ToUpper(form.mnemonic))
}

// A complete physical sequence retains the SP and registers visible at trap
// entry, including when a handler resumes at a subsequent source instruction.
func lowerARM64PhysicalExceptionLeaf(b *strings.Builder, fn Func, sig FuncSig) (bool, error) {
	if len(fn.Instrs) < 2 || fn.Instrs[0].Op != OpTEXT {
		return false, nil
	}
	first, err := parseARM64Exception(fn.Instrs[1])
	if err != nil {
		return true, err
	}
	if !first.needsPhysicalEntry() {
		return false, nil
	}
	if (fn.FrameSize != 0 && fn.FrameSize != -8) ||
		!arm64SourceFrameFlagsKnown(fn) || fn.ArgSize != 0 ||
		sig.Ret != Void || len(sig.Args) != 0 || len(sig.ArgRegs) != 0 ||
		len(sig.Frame.Params) != 0 || len(sig.Frame.Results) != 0 ||
		sig.ARM64GoRegisterABI != nil || sig.ARM64ClosureABI != nil {
		return true, first.physicalContextError()
	}

	program := []string{first.assembly()}
	last := first
	needsEL3 := first.needsEL3()
	for index, ins := range fn.Instrs[2:] {
		form, err := parseARM64Exception(ins)
		if err != nil {
			return true, err
		}
		if form.mnemonic != "" {
			program = append(program, form.assembly())
			last = form
			needsEL3 = needsEL3 || form.needsEL3()
			continue
		}
		if index+3 != len(fn.Instrs) || len(ins.Args) != 0 {
			return true, first.physicalContextError()
		}
		switch ins.Op {
		case OpRET:
			program = append(program, "ret")
		case "UNDEF":
			program = append(program, fmt.Sprintf("udf #%d", ins.arm64RawUndefinedImmediate))
		default:
			return true, first.physicalContextError()
		}
		last = arm64ExceptionForm{}
	}
	switch last.mnemonic {
	case "hvc", "smc", "brk":
		return true, last.physicalContextError()
	}

	features := ""
	if needsEL3 {
		features = ` "target-features"="+el3"`
	}
	fmt.Fprintf(b, "define void %s() naked noinline%s {\nentry:\n", llvmGlobal(sig.Name), features)
	fmt.Fprintf(b, "  call void asm sideeffect %q, %q()\n", strings.Join(program, "; "), "~{memory}")
	b.WriteString("  unreachable\n}\n")
	return true, nil
}

func (c *arm64Ctx) lowerExceptionForm(form arm64ExceptionForm) error {
	if form.needsPhysicalEntry() {
		return form.physicalContextError()
	}
	c.emitARM64Exception(form.mnemonic, form.immediate)
	return nil
}

func (c *arm64Ctx) emitARM64Exception(mnemonic string, immediate uint16) {
	form := arm64ExceptionForm{mnemonic: mnemonic, immediate: immediate}
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q()\n", form.assembly(), "~{memory}")
}

func (c *arm64Ctx) lowerARM64Exception(op Op, ins Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "HLT", "HVC", "SMC", "DCPS1", "DCPS2", "DCPS3", "DRPS", "ERET", "BRK":
		form, err := parseARM64Exception(ins)
		if err != nil {
			return true, false, err
		}
		// An ordinary BRK can resume at the next source instruction.
		return true, false, c.lowerExceptionForm(form)
	case "UNDEF":
		if strings.ToUpper(string(ins.Op)) != "UNDEF" || len(ins.Args) != 0 {
			return true, false, fmt.Errorf("arm64 UNDEF takes no operands or suffix: %q", ins.Raw)
		}
		c.emitARM64Exception("udf", ins.arm64RawUndefinedImmediate)
		c.b.WriteString("  unreachable\n")
		return true, true, nil
	default:
		return false, false, nil
	}
}
