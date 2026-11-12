package plan9asm

import (
	"errors"
	"fmt"
	"strings"
)

type x86COMISpec struct {
	bits   int
	vector bool
}

var x86COMISpecs = map[Op]x86COMISpec{
	"COMISS": {32, false}, "UCOMISS": {32, false},
	"COMISD": {64, false}, "UCOMISD": {64, false},
	"VCOMISS": {32, true}, "VUCOMISS": {32, true},
	"VCOMISD": {64, true}, "VUCOMISD": {64, true},
}

// Go's yxm and _yvcomisd rows have two read-only scalar operands, not a
// vector destination. EVEX adds register-only SAE, never masking/broadcast.
type x86COMIForm struct {
	spec      x86COMISpec
	name      string
	sae, evex bool
}

func x86COMIProperties(ins Instr, arch string) (x86COMIForm, bool, error) {
	name, suffix, dotted := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	spec, known := x86COMISpecs[Op(name)]
	form := x86COMIForm{spec: spec, name: name, sae: suffix == "SAE", evex: ins.x86ScalarFlagCompareEVEX || dotted}
	if !known {
		return form, false, nil
	}
	fail := func() (x86COMIForm, bool, error) {
		return form, true, fmt.Errorf("%s %s outside Go scalar flag-compare grammar: %q", arch, ins.Op, ins.Raw)
	}
	if arch != "386" && arch != "amd64" || len(ins.Args) != 2 ||
		dotted && (!spec.vector || suffix != "SAE" || ins.Args[0].Kind != OpReg) {
		return fail()
	}
	var contextErr error
	for index, operand := range ins.Args {
		if operand.Kind == OpReg {
			register, valid := amd64ParseXReg(operand.Reg)
			if !valid || !spec.vector && (register >= 16 || arch == "386" && register >= 8) {
				return fail()
			}
			if arch == "386" && register >= 8 {
				contextErr = fmt.Errorf("%w: %s lacks physical mode32 high-X identity", ErrProbeNeedsContext, ins.Op)
			}
			form.evex = form.evex || register >= 16
			continue
		}
		if index != 0 || !isAMD64MemoryOperand(operand) {
			return fail()
		}
		if operand.Kind == OpMem {
			if operand.Mem.OffRaw != "" || operand.Mem.IndexExt != "" {
				return fail()
			}
			if err := x86SymbolIndexedMemoryError(operand.Mem, arch); err != nil {
				if !errors.Is(err, ErrProbeNeedsContext) {
					return form, true, err
				}
				contextErr = err
				continue
			}
			if arch == "386" && strings.HasSuffix(operand.Mem.Sym, "(SB)") {
				operand.Mem.Base = ""
			}
		}
		if !x86PackedShiftMemoryValid(operand, arch) {
			return fail()
		}
	}
	return form, true, contextErr
}

func validateX86COMIFile(file *File, options Options) error {
	if file == nil || file.Arch != ArchAMD64 {
		return nil
	}
	needed := false
	var contextErr error
	for _, function := range file.Funcs {
		for _, instruction := range function.Instrs {
			_, known, err := x86COMIProperties(instruction, options.Goarch)
			if known && err != nil {
				if !errors.Is(err, ErrProbeNeedsContext) {
					return fmt.Errorf("%s: %w", function.Sym, err)
				}
				if contextErr == nil {
					contextErr = fmt.Errorf("%s: %w", function.Sym, err)
				}
			}
			needed = needed || known
		}
	}
	if contextErr != nil {
		return contextErr
	}
	if needed && !x86ScalarFloatIntegerNativeTarget(options.Goarch, options.TargetTriple) {
		return fmt.Errorf("%w: scalar flag comparison requires its native x86 MXCSR target", ErrProbeNeedsContext)
	}
	return nil
}

func x86TypedCOMIByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	name, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if _, known := x86COMISpecs[Op(name)]; !known {
		return x86TypedByteEffect{}, false, nil
	}
	if !strings.EqualFold(string(op), string(ins.Op)) {
		return x86TypedByteEffect{}, true, fmt.Errorf("scalar flag comparison effect/source mismatch")
	}
	form, known, err := x86COMIProperties(ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	width := int64(form.spec.bits / 8)
	return x86TypedByteEffect{operands: []x86TypedByteOperand{
		{index: 0, operand: ins.Args[0], width: width, read: true},
		{index: 1, operand: ins.Args[1], width: width, read: true},
	}, flagsDefined: x86ByteFlagsAll, requiresResultProof: true}, true, nil
}

func x86ResultCOMIStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	return x86ResultCOMIStepWithRead(ins, state, owned, arch, false)
}

// Only the paired native comparison supplies conditional numerical inputs.
// Its complete opcode preserves the scalar read, MXCSR and exception effects;
// no memory backing or reusable input fact reaches the declaration observer.
func x86ResultCOMIStepWithRead(ins Instr, state *x86ResultState, owned []bool, arch string, nativeRead bool) (bool, bool) {
	form, known, err := x86COMIProperties(ins, arch)
	if !known || err != nil {
		return false, known
	}
	width := int64(form.spec.bits / 8)
	for _, operand := range ins.Args {
		if operand.Kind == OpReg {
			index, _ := amd64ParseXReg(operand.Reg)
			mask := x86CallerVectorByteMask(width)
			if state.vectorBytes(index)&mask != mask {
				return false, true
			}
		} else if !x86ResultReadWithNativeContinuation(ins, operand, width, state, owned, arch, nativeRead) {
			return false, true
		}
	}
	state.flags = x86ByteFlagsAll
	return true, true
}
