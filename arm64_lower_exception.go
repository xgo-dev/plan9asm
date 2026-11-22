package plan9asm

import (
	"fmt"
	"strings"
)

type arm64RawException struct {
	mnemonic  string
	immediate uint16
}

func decodeARM64RawException(word uint32) (arm64RawException, bool) {
	base := word &^ (0xffff << 5)
	mnemonic := ""
	switch base {
	case 0xd4000002:
		mnemonic = "hvc"
	case 0xd4000003:
		mnemonic = "smc"
	case 0xd4200000:
		mnemonic = "brk"
	default:
		return arm64RawException{}, false
	}
	return arm64RawException{mnemonic: mnemonic, immediate: uint16(word >> 5)}, true
}

func (c *arm64Ctx) emitARM64Exception(mnemonic string, immediate uint16) {
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q()\n", fmt.Sprintf("%s #%d", mnemonic, immediate), "~{memory}")
}

func (c *arm64Ctx) lowerRawException(form arm64RawException) error {
	c.emitARM64Exception(form.mnemonic, form.immediate)
	return nil
}

func arm64ExceptionReturnMnemonic(ins Instr) (string, error) {
	switch op := arm64ControlOp(ins); op {
	case "ERET", "DRPS":
		if ins.Op != op || len(ins.Args) != 0 {
			return "", fmt.Errorf("arm64 %s takes no operands or suffix: %q", op, ins.Raw)
		}
		return strings.ToLower(string(op)), nil
	case OpWORD:
		if len(ins.Args) != 1 || ins.Args[0].Kind != OpImm {
			return "", nil
		}
		var mnemonic string
		switch uint32(ins.Args[0].Imm) {
		case 0xd69f03e0:
			mnemonic = "eret"
		case 0xd6bf03e0:
			mnemonic = "drps"
		default:
			return "", nil
		}
		_, err := arm64RawWordValue(ins)
		return mnemonic, err
	default:
		return "", nil
	}
}

// Exception return leaves the function without an LLVM epilogue. A leaf
// consisting of the return itself can retain the incoming physical state.
func lowerARM64ExceptionReturnLeaf(b *strings.Builder, fn Func, sig FuncSig) (bool, error) {
	if len(fn.Instrs) < 2 || fn.Instrs[0].Op != OpTEXT {
		return false, nil
	}
	mnemonic, err := arm64ExceptionReturnMnemonic(fn.Instrs[1])
	if err != nil {
		return true, err
	}
	if mnemonic == "" {
		return false, nil
	}
	// A trailing plain RET leaves the exposed instruction layout intact.
	trailing := fn.Instrs[2:]
	bodyClosed := len(trailing) == 0 ||
		len(trailing) == 1 && trailing[0].Op == OpRET && len(trailing[0].Args) == 0
	if !bodyClosed || (fn.FrameSize != 0 && fn.FrameSize != -8) ||
		!arm64SourceFrameFlagsKnown(fn) || fn.ArgSize != 0 ||
		sig.Ret != Void || len(sig.Args) != 0 || len(sig.ArgRegs) != 0 ||
		len(sig.Frame.Params) != 0 || len(sig.Frame.Results) != 0 ||
		sig.ARM64GoRegisterABI != nil || sig.ARM64ClosureABI != nil {
		return true, fmt.Errorf("%w: ARM64 exception return requires a frameless physical entry", ErrProbeNeedsContext)
	}
	if len(trailing) != 0 {
		mnemonic += "; ret"
	}
	fmt.Fprintf(b, "define void %s() naked noinline {\nentry:\n", llvmGlobal(sig.Name))
	fmt.Fprintf(b, "  call void asm sideeffect %q, %q()\n", mnemonic, "~{memory}")
	b.WriteString("  unreachable\n}\n")
	return true, nil
}

func (c *arm64Ctx) lowerARM64Exception(op Op, ins Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "HLT", "HVC", "SMC", "DCPS1", "DCPS2", "DCPS3":
		if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) > 1 {
			return true, false, fmt.Errorf("arm64 %s accepts no operand or one constant operand, with no suffix: %q", op, ins.Raw)
		}
		var immediate uint16
		if len(ins.Args) == 1 {
			if ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" || ins.Args[0].ImmIsFloat {
				return true, false, fmt.Errorf("arm64 %s operand must be a constant: %q", op, ins.Raw)
			}
			immediate = uint16(ins.Args[0].Imm)
		}
		mnemonic := strings.ToLower(string(op))
		c.emitARM64Exception(mnemonic, immediate)
		if op == "HLT" || strings.HasPrefix(string(op), "DCPS") {
			c.b.WriteString("  unreachable\n")
			return true, true, nil
		}
		return true, false, nil
	case "BRK":
		if strings.ToUpper(string(ins.Op)) != "BRK" || len(ins.Args) > 1 {
			return true, false, fmt.Errorf("arm64 BRK accepts no operand or one constant operand, with no suffix: %q", ins.Raw)
		}
		var immediate uint64
		if len(ins.Args) == 1 {
			if ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" || ins.Args[0].ImmIsFloat {
				return true, false, fmt.Errorf("arm64 BRK operand must be a constant: %q", ins.Raw)
			}
			immediate = uint64(ins.Args[0].Imm) & 0xffff
		}
		// A debugger or signal handler may resume after BRK, so keep the
		// following source instructions reachable.
		c.emitARM64Exception("brk", uint16(immediate))
		return true, false, nil
	case "DRPS", "ERET":
		if _, err := arm64ExceptionReturnMnemonic(ins); err != nil {
			return true, false, err
		}
		return true, false, fmt.Errorf("%w: ARM64 %s requires a physical entry with no compiler frame", ErrProbeNeedsContext, op)
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
