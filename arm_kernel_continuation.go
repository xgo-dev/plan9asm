package plan9asm

import (
	"fmt"
	"strings"
)

// A source B retains its Go frame and its current physical LR. It is not a
// Go RET helper, which restores the saved LR and removes the caller frame.
// Until an explicit machine-state bridge models those continuations, native
// tails require the same zero-frame leaf boundary used by Go's ARM obj5.go.
func proveARMKernelContinuation(fn Func) error {
	hasCall, hasTail, nonLeaf := false, false, false
	for _, ins := range fn.Instrs {
		if ins.armKernelCall != nil {
			hasCall = true
			hasTail = hasTail || ins.armKernelCall.tail
		}
		op, _, _, _ := armDecodeOp(string(ins.Op))
		switch op {
		case "BL", "CALL", "BX", "DIV", "DIVU", "MOD", "MODU", "DUFFZERO", "DUFFCOPY":
			// Go's leaf scan includes unreachable instructions as well.
			nonLeaf = true
		}
	}
	if !hasCall {
		return nil
	}
	noFrame, err := armKernelSourceNoFrame(fn)
	if err != nil {
		return err
	}
	if hasTail && (fn.FrameSize != 0 && fn.FrameSize != -4 || nonLeaf) {
		return fmt.Errorf("%w: ARM kernel tail in %q needs a zero-frame leaf Go SP/LR continuation", ErrProbeNeedsContext, fn.Sym)
	}
	for _, ins := range fn.Instrs {
		if ins.Op == OpWORD || ins.Op == OpBYTE || ins.Op == "LONG" {
			return fmt.Errorf("%w: ARM kernel continuation in %q needs a decoded raw SP/LR effect contract: %s", ErrProbeNeedsContext, fn.Sym, ins.Raw)
		}
		if ins.armKernelCall != nil && !ins.armKernelCall.tail && noFrame {
			return fmt.Errorf("%w: ARM kernel BL/CALL in NOFRAME %q overwrites native LR without a source return bridge", ErrProbeNeedsContext, fn.Sym)
		}
		for _, arg := range ins.Args {
			if armKernelOperandUsesReg(arg, "R14") {
				return fmt.Errorf("%w: ARM kernel continuation in %q explicitly observes or replaces native LR: %s", ErrProbeNeedsContext, fn.Sym, ins.Raw)
			}
			if armKernelOperandUsesReg(arg, "R13") || armKernelOperandUsesReg(arg, SP) {
				return fmt.Errorf("%w: ARM kernel continuation in %q needs explicit source SP backing/provenance: %s", ErrProbeNeedsContext, fn.Sym, ins.Raw)
			}
		}
	}
	return nil
}

func armKernelSourceNoFrame(fn Func) (bool, error) {
	if len(fn.Instrs) == 0 || fn.Instrs[0].Op != OpTEXT {
		return false, fmt.Errorf("%w: ARM kernel caller %q has no source TEXT flags", ErrProbeNeedsContext, fn.Sym)
	}
	parts := splitTopLevelCSV(fn.Instrs[0].Raw)
	flags := uint64(0)
	if len(parts) == 3 {
		expression := globlFlagName.ReplaceAllStringFunc(parts[1], func(name string) string {
			if value, ok := goTextFlagValues[name]; ok {
				return value
			}
			return name
		})
		var ok bool
		flags, ok = parseImmExpr(strings.TrimSpace(expression))
		if !ok {
			return false, fmt.Errorf("%w: ARM kernel caller %q has unresolved TEXT flags %q", ErrProbeNeedsContext, fn.Sym, parts[1])
		}
	} else if len(parts) != 2 {
		return false, fmt.Errorf("%w: ARM kernel caller %q has malformed TEXT metadata", ErrProbeNeedsContext, fn.Sym)
	}
	return fn.FrameSize == -4 || flags&512 != 0, nil
}

func armKernelOperandUsesReg(arg Operand, reg Reg) bool {
	switch arg.Kind {
	case OpReg, OpRegShift, OpRegExtend:
		return arg.Reg == reg || arg.ShiftReg == reg
	case OpMem:
		if arg.Mem.Base == reg || arg.Mem.Index == reg {
			return true
		}
		if shift, ok := armMemoryShift(arg.Mem); ok {
			return shift.Reg == reg || shift.ShiftReg == reg
		}
	case OpRegList:
		for _, item := range arg.RegList {
			if item == reg {
				return true
			}
		}
	}
	return false
}
