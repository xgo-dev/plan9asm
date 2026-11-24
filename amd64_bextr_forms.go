package plan9asm

func x86BEXTRProperties(op Op, ins Instr, arch string) (x86ScalarBitFieldForm, bool, error) {
	return x86ScalarBitFieldFamilyProperties(op, ins, arch, x86BitFieldExtract)
}

func x86TypedScalarBitFieldByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86ScalarBitFieldProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	width := int64(form.bits / 8)
	return x86TypedByteEffect{
		operands: []x86TypedByteOperand{
			{index: 0, operand: form.control, width: form.spec.controlBytes, read: true},
			{index: 1, operand: form.source, width: width, read: true},
			{index: 2, operand: form.destination, width: width, write: true},
		},
		flagsDefined:        form.spec.flagsDefined,
		flagsKilled:         x86ByteFlagsAll,
		requiresResultProof: true,
	}, true, nil
}

// A paired native read supplies numerical source bytes only if it continues.
// It grants no caller, extent, raw-entry or reusable native-memory capability.
