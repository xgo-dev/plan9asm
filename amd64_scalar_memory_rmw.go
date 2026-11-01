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
	if !known || !x86OrdinaryNativeMemoryOperand(form.destination, c.goarch) {
		if form.spec.stem == "INC" || form.spec.stem == "DEC" {
			// Preserve the existing logical GP/FP/AUTO byte-view consumer;
			// only actual native memory gets the new paired access above it.
			value, err := c.evalIntSized(destination, typ)
			return value, func(value string) error {
				return c.storeScalarIntegerOperand(destination, typ, value)
			}, err
		}
		return c.loadIntDestination(destination, typ)
	}
	if ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride {
		return "", nil, fmt.Errorf("%w: scalar RMW needs its original native address size", ErrProbeNeedsContext)
	}
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(form.destination)
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

func (c *amd64Ctx) lowerScalarMemoryRMW(op Op, ins Instr) (bool, bool, error) {
	if c.namedAtomicLock {
		return false, false, nil
	}
	form, known, err := x86ScalarMemoryRMWProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	local := ins
	local.Op = op
	local.Args = append([]Operand(nil), ins.Args...)
	if !form.spec.unary {
		if form.source.Kind == OpReg && form.source.Reg != ins.Args[0].Reg &&
			x86LogicalSourceFrameRegister(form.source.Reg, c.goarch) {
			return true, false, fmt.Errorf("%w: RMW byte source needs its physical SP/BP role", ErrProbeNeedsContext)
		}
		local.Args[0] = form.source // Only local dispatch, never rewrite either source snapshot.
	}
	switch form.spec.stem {
	case "ADD", "SUB":
		return c.lowerScalarAddSub(op, local)
	case "ADC", "SBB":
		return c.lowerScalarADCSBB(op, local)
	case "INC", "DEC":
		return c.lowerScalarIncDec(op, local)
	case "NEG", "NOT":
		return c.lowerScalarUnaryYmb(op, local)
	}

	// The remaining shared rows are AND/OR/XOR, not implicitly locked atomics.
	typ := amd64IntegerTypeForBits(form.spec.bits)
	source, err := c.evalIntSized(form.source, typ)
	if err != nil {
		return true, false, err
	}
	old, store, err := c.loadScalarRMWDestination(op, local, form.destination, typ)
	if err != nil {
		return true, false, err
	}
	operation := map[string]string{"AND": "and", "OR": "or", "XOR": "xor"}[form.spec.stem]
	if operation == "" {
		return true, false, fmt.Errorf("unregistered scalar memory RMW effect %s", op)
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", result, operation, typ, old, source)
	value := "%" + result
	if err := store(value); err != nil {
		return true, false, err
	}
	c.clearX86StatusFlags(x86StatusCF | x86StatusOF)
	zero, sign := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, 0\n", zero, typ, value)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zero, c.flagsZSlot)
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, 0\n", sign, typ, value)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", sign, c.flagsSltSlot)
	c.setParityFlagSized(typ, value)
	return true, false, nil // AF remains architecturally undefined, not an input fact.
}

func x86LoweredScalarMemoryRMW(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	form, known, err := x86ScalarMemoryRMWProperties(ins.Op, ins, arch)
	if !known || err != nil || !x86OrdinaryNativeMemoryOperand(form.destination, arch) {
		return false, known && err != nil
	}
	if !x86ResultNamedPredicateInstruction(ins) || ins.x86NumericalRead != nil ||
		!x86ResultNativeRMWAddress(ins, form.destination, state, owned, arch) {
		return false, true
	}
	if !form.spec.unary && !x86ResultRead(form.source, int64(form.spec.bits/8), state, owned, arch) ||
		(form.spec.stem == "ADC" || form.spec.stem == "SBB") && state.flags&x86ByteFlagCF == 0 {
		return false, true
	}
	state.flags = state.flags&^form.spec.flagsKilled | form.spec.flagsDefined
	return true, true // No GP, logical storage, pointee or reusable memory facts are added.
}
