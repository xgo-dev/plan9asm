package plan9asm

import "fmt"

// The ordinary memory destinations use the complete existing scalar grammar.
// Bit strings and bound LOCK keep their independent effects and dispatch.
func x86ScalarMemoryRMWProperties(op Op, ins Instr, arch string) (x86LockScalarRMWForm, bool, error) {
	form, known, err := x86LockScalarRMWProperties(op, ins, arch)
	if !known || form.spec.bitString {
		return form, false, nil
	}
	if err != nil {
		return form, true, err
	}
	return form, isAMD64MemoryOperand(form.destination), nil
}

func (c *amd64Ctx) loadScalarRMWDestination(op Op, ins Instr, destination Operand, typ LLVMType) (string, func(string) error, error) {
	form, known, err := x86ScalarMemoryRMWProperties(op, ins, c.goarch)
	if err != nil {
		return "", nil, err
	}
	if known && c.nativeMemoryOperand(ins, len(ins.Args)-1) {
		return c.loadTypedScalarRMWDestination(ins, form.destination, typ)
	}
	if form.spec.stem == "INC" || form.spec.stem == "DEC" {
		// INC/DEC retains its logical GP/FP/AUTO byte-view consumer.
		value, err := c.evalIntSized(destination, typ)
		return value, func(value string) error {
			return c.storeScalarIntegerOperand(destination, typ, value)
		}, err
	}
	return c.loadIntDestination(destination, typ)
}

func (c *amd64Ctx) loadTypedScalarRMWDestination(ins Instr, destination Operand, typ LLVMType) (string, func(string) error, error) {
	if !isAMD64MemoryOperand(destination) || !c.nativeMemoryOperand(ins, len(ins.Args)-1) {
		return c.loadIntDestination(destination, typ)
	}
	if ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride {
		return "", nil, fmt.Errorf("%w: scalar RMW needs its original native address size", ErrProbeNeedsContext)
	}
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(destination)
	if err != nil {
		return "", nil, err
	}
	loaded := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load volatile %s, %s %s, align 1\n", loaded, typ, pointerType, pointer)
	return "%" + loaded, func(value string) error {
		fmt.Fprintf(c.b, "  store volatile %s %s, %s %s, align 1\n", typ, value, pointerType, pointer)
		return nil
	}, nil
}

func x86LoweredScalarMemoryRMW(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	form, known, err := x86ScalarMemoryRMWProperties(ins.Op, ins, arch)
	if !known || err != nil || !x86OrdinaryNativeMemoryOperand(form.destination, arch) {
		return false, known && err != nil
	}
	if !x86ResultNamedPredicateInstruction(ins) || ins.x86NumericalRead != nil ||
		!x86ResultNativeRMWAddress(ins, form.destination, state, owned, arch, form.source) {
		return false, true
	}
	if !form.spec.unary && !x86ResultRead(form.source, int64(form.spec.bits/8), state, owned, arch) ||
		(form.spec.stem == "ADC" || form.spec.stem == "SBB") && state.flags&x86ByteFlagCF == 0 {
		return false, true
	}
	state.flags = state.flags&^form.spec.flagsKilled | form.spec.flagsDefined
	return true, true // No GP, logical storage, pointee or reusable memory facts are added.
}
