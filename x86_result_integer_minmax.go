package plan9asm

func x86RawIntegerMinMaxSource(ins Instr, arch string) bool {
	form, known, err := x86IntegerMinMaxProperties(ins.Op, ins, arch)
	return known && err == nil && !form.legacy && ins.x86Encoded && x86RawOrdinaryVectorSource(ins, arch)
}

// A decoder-local constant keeps its existing exact DATA/return consumer.
// This shape supplies no missing input, standalone or native-address role.
func x86RawIntegerMinMaxLiteralForm(ins Instr, arch string) bool {
	if !x86RawLiteralSourceShape(ins, arch) || !x86RawReturnDecodedReadIdentity(ins) {
		return false
	}
	form, known, err := x86IntegerMinMaxProperties(ins.Op, ins, arch)
	return known && err == nil && !form.legacy && form.memory == form.first &&
		ins.x86RIPMemoryRead.source == form.first && ins.x86RIPMemoryRead.width == int64(form.memoryBytes)
}

func x86ResultIntegerMinMaxStep(ins Instr, state *x86ResultState, owned []bool, arch string, native bool) (bool, bool) {
	form, known, err := x86IntegerMinMaxProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		literal := state.loweredStaticReads != nil && x86RawIntegerMinMaxLiteralForm(ins, arch)
		if !literal && (!native || !x86RawIntegerMinMaxSource(ins, arch)) {
			return false, true
		}
		// Preserve the already-validated physical form. This local numerical
		// projection does not reparse mode32 bytes as named source operands.
		ins.x86Encoded, ins.x86SourceRaw = false, nil
	}
	if form.legacy && form.memory >= 0 {
		source := ins.Args[form.memory]
		if source.Kind == OpFP || source.Kind == OpMem && !x86OrdinaryNativeMemoryOperand(source, arch) {
			return false, true // Virtual bytes cannot supply original aligned m128 backing.
		}
		if native && !x86ResultPackedVectorRead(ins.Args[form.second], 16, state, owned, arch) {
			return false, true // A dead original RMW still consumes its old destination.
		}
	}
	return x86ResultPackedLaneArithmeticStepWithRead(ins, form.x86PackedBinaryForm,
		form.spec.laneBits, state, owned, arch, native), true
}
