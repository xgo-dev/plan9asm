package plan9asm

import "fmt"

// The validated shift grammar supplies the exact physical width and operand
// index. Preserve a native access even at count zero or when its result dies.
// Logical FP/AUTO storage keeps its existing independent byte-view contracts.
func (c *amd64Ctx) loadScalarShiftOperand(ins Instr, index int, typ LLVMType) (string, func(string) error, error) {
	operand := ins.Args[index]
	store := func(value string) error {
		return c.storeScalarIntegerOperand(operand, typ, value)
	}
	if operand.Kind == OpFP && x86ResultNamedPredicateInstruction(ins) {
		if value, handled, err := c.loadIntegerFPBytesMode(operand.FPOffset, typ, true); handled || err != nil {
			return value, store, err
		}
	}
	if !isAMD64MemoryOperand(operand) || operand.Kind == OpFP ||
		!(x86OrdinaryNativeMemoryOperand(operand, c.goarch) ||
			x86CallerMemoryCertified(ins, index) || c.fixedLocalMemoryCertified(ins, index)) {
		value, err := c.evalIntSized(operand, typ)
		return value, store, err
	}
	if ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride {
		return "", nil, fmt.Errorf("%w: scalar shift needs its original native address size", ErrProbeNeedsContext)
	}
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(operand)
	if err != nil {
		return "", nil, err
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load volatile %s, %s %s, align 1\n", value, typ, pointerType, pointer)
	return "%" + value, func(value string) error {
		fmt.Fprintf(c.b, "  store volatile %s %s, %s %s, align 1\n", typ, value, pointerType, pointer)
		return nil
	}, nil
}

// Continuing the paired access supplies numerical values, not pointee bounds,
// reusable memory facts, a raw entry or a declaration-only read permission.
func x86LoweredScalarShiftMemory(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	form, known, err := x86ScalarShiftProperties(ins.Op, ins, arch)
	if !known || err != nil || !form.hasMemory() {
		return false, known && err != nil
	}
	nativeDestination := x86OrdinaryNativeMemoryOperand(form.destination, arch)
	nativeSource := form.sourceIndex >= 0 && x86OrdinaryNativeMemoryOperand(form.source, arch)
	if !nativeDestination && !nativeSource {
		return false, false // Existing logical storage consumes the shared descriptor.
	}
	if !x86ResultNamedPredicateInstruction(ins) || ins.x86NumericalRead != nil {
		return false, true
	}
	return x86LoweredScalarShiftTransfer(ins, form, state, owned, resultOffset, arch), true
}

func x86LoweredScalarShiftTransfer(ins Instr, form x86ScalarShiftForm, state *x86ResultState,
	owned []bool, resultOffset int64, arch string) bool {
	effect := form.inputEffect()
	if state.flags&effect.flagsRead != effect.flagsRead {
		return false
	}
	nativeDestination := x86OrdinaryNativeMemoryOperand(form.destination, arch)
	if !x86ResultNamedPredicateInstruction(ins) || ins.x86NumericalRead != nil {
		return false
	}
	// Check every input and address before overwriting aliased registers.
	for _, input := range effect.operands {
		if !input.read {
			continue
		}
		if nativeDestination && input.index == form.destinationIndex {
			if !x86ResultIncomingPointerAddressIdentity(input.operand, state, arch) {
				return false
			}
			continue
		}
		if input.operand.Kind == OpReg {
			index, _, valid := x86ResultGP(input.operand.Reg, input.width, arch)
			// The independent shape clone retains original entry pointer
			// roles, not this instruction's reaching register roles. Earlier
			// source writes may already have replaced them. Only real
			// dataflow states decide whether an input is opaque or numerical.
			if !valid || !state.shapeOnly && state.pointerGP[index] {
				return false
			}
		}
		if !x86ResultReadWithNativeContinuation(ins, input.operand, input.width, state, owned, arch, true) {
			return false
		}
	}
	if !nativeDestination && !x86ResultStore(form.destination, int64(form.bits/8), state, owned, resultOffset, arch) {
		return false
	}
	state.flags = form.outcome().availableFlags(state.flags)
	return true
}
