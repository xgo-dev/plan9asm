package plan9asm

import (
	"fmt"
	"reflect"
)

// A source shape alone supplies no input permission. The typed family, complete
// source replay and independent raw-return/DATA consumer remain mandatory.
func x86RawLiteralSourceShape(ins Instr, arch string) bool {
	return arch == "amd64" && ins.x86Encoded && ins.x86RIPLiteral &&
		ins.x86SourceRaw != nil && ins.x86RawNearReturn == nil && ins.x86AddressBits == 0 &&
		!ins.x86UnboundAddressOverride && ins.x86SegmentPrefix == 0
}

// Raw replay keeps decoder operands before the normalizer allocates a module
// DATA symbol. Bind that single private relocation without rewriting the
// immutable decoder checkpoint or accepting another changed source operand.
func x86RawLiteralSourceIdentity(ins Instr, arch string) bool {
	if !x86RawLiteralSourceShape(ins, arch) || !x86RawReturnDecodedReadIdentity(ins) {
		return false
	}
	origin, read := ins.x86SourceRaw, ins.x86RIPMemoryRead
	if origin.op != ins.Op || len(origin.args) != len(ins.Args) ||
		origin.vectorBytes != ins.x86VectorBytes || origin.addressBits != ins.x86AddressBits {
		return false
	}
	for index, operand := range origin.args {
		if index == read.source {
			pending := Operand{Kind: OpSym, Sym: "·__plan9asm_raw_literal_pending(SB)"}
			if !reflect.DeepEqual(operand, pending) {
				return false
			}
		} else if !reflect.DeepEqual(operand, ins.Args[index]) {
			return false
		}
	}
	return true
}

// RIP constants are a decoder role, never a named-immediate broadcast form.
func x86RawBroadcastLiteralForm(ins Instr, arch string) bool {
	if !x86RawLiteralSourceShape(ins, arch) {
		return false
	}
	form, known, err := x86BroadcastProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false
	}
	if ins.Args[0].Kind == OpImm {
		return ins.x86SourceRaw.op == ins.Op && reflect.DeepEqual(ins.x86SourceRaw.args, ins.Args) &&
			(form.kind == x86BroadcastInteger || form.kind == x86BroadcastFloat)
	}
	return form.kind == x86BroadcastBlock && x86RawReturnDecodedReadIdentity(ins) &&
		ins.x86RIPMemoryRead.source == 0 && ins.x86RIPMemoryRead.width == int64(form.sourceBytes)
}

func x86RawLogicalLiteralForm(ins Instr, arch string) bool {
	if !x86RawLiteralSourceShape(ins, arch) || !x86RawReturnDecodedReadIdentity(ins) {
		return false
	}
	form, known, err := x86PackedLogicalProperties(ins, arch)
	return known && err == nil && !form.legacy && !form.mmx && form.memory >= 0 &&
		ins.x86RIPMemoryRead.source == form.first && ins.x86RIPMemoryRead.width == int64(form.memoryBytes)
}

func x86RawByteShiftLiteralForm(ins Instr, arch string) bool {
	if !x86RawLiteralSourceShape(ins, arch) || !x86RawReturnDecodedReadIdentity(ins) ||
		!x86RawPackedShiftEncodingSource(ins, arch) {
		return false
	}
	form, known, err := x86PackedShiftProperties(ins.Op, ins, arch)
	return known && err == nil && form.countMode == x86PackedShiftBytes &&
		!form.legacy && !form.mmx && form.memory == form.data &&
		ins.x86RIPMemoryRead.source == form.data && ins.x86RIPMemoryRead.width == int64(form.memoryBytes)
}

func x86RawIntegerCompareLiteralForm(ins Instr, arch string) bool {
	if !x86RawLiteralSourceShape(ins, arch) || !x86RawReturnDecodedReadIdentity(ins) {
		return false
	}
	form, known, err := x86PackedIntegerCompareProperties(ins.Op, ins, arch)
	return known && err == nil && !form.legacy && !form.mmx && form.memory >= 0 &&
		ins.x86RIPMemoryRead.source == form.first && ins.x86RIPMemoryRead.width == int64(form.memoryBytes)
}

func x86RawArithmeticLiteralForm(ins Instr, arch string) bool {
	if !x86RawLiteralSourceShape(ins, arch) || !x86RawReturnDecodedReadIdentity(ins) {
		return false
	}
	add, known, err := x86PackedIntegerAddProperties(ins, arch)
	form := add.x86PackedBinaryForm
	if !known {
		subtract, subKnown, subErr := x86PackedSubtractProperties(ins, arch)
		form, known, err = subtract.x86PackedBinaryForm, subKnown, subErr
	}
	return known && err == nil && !form.legacy && !form.mmx && form.memory >= 0 &&
		ins.x86RIPMemoryRead.source == form.first && ins.x86RIPMemoryRead.width == int64(form.memoryBytes)
}

func x86RawFloatCompareLiteralForm(ins Instr, arch string) bool {
	if !x86RawLiteralSourceShape(ins, arch) || !x86RawReturnDecodedReadIdentity(ins) {
		return false
	}
	form, known, err := x86FloatCompareProperties(ins, arch)
	return known && err == nil && !form.legacy && form.memory >= 0 &&
		ins.x86RIPMemoryRead.source == form.first && ins.x86RIPMemoryRead.width == int64(form.memoryBytes)
}

// A scalar flag comparison consumes only the exact decoder-owned literal.
// Its physical generation and scalar width do not grant a native pointer role.
func x86RawCOMILiteralForm(ins Instr, arch string) bool {
	if !x86RawLiteralSourceIdentity(ins, arch) {
		return false
	}
	form, known, err := x86COMIProperties(ins, arch)
	return known && err == nil && form.spec.vector && ins.Args[0].Kind == OpSym &&
		ins.x86SourceRaw.comi.arch == arch && ins.x86SourceRaw.comi == x86COMIRawIdentity(ins, arch) &&
		ins.x86RIPMemoryRead.source == 0 && ins.x86RIPMemoryRead.width == int64(form.spec.bits/8)
}

// Scalar SQRT and packed/scalar binary arithmetic share an exact decoded first
// operand, not native-address authority. MIN/MAX keeps its distinct controls
// and physical generation; FP16, packed SQRT and legacy remain separate roles.
func x86RawBinaryFloatLiteralForm(ins Instr, arch string) bool {
	if !x86RawLiteralSourceIdentity(ins, arch) {
		return false
	}
	f, known, err := x86SqrtProperties(ins, arch)
	if known && (!f.scalar || f.bits != 32 && f.bits != 64) {
		return false
	}
	if !known {
		addsub, recognized, parseErr := x86FloatAddSubProperties(ins, arch)
		f, known, err = addsub.x86FloatBinaryForm, recognized, parseErr
	}
	if !known {
		muldiv, recognized, parseErr := x86FloatMulDivProperties(ins, arch)
		f, known, err = muldiv.x86FloatBinaryForm, recognized, parseErr
	}
	if !known {
		minmax, recognized, parseErr := x86FloatMinMaxProperties(ins, arch)
		f, known, err = minmax.x86FloatBinaryForm, recognized, parseErr
		if known && !x86RawFloatMinMaxEncodingSource(ins, arch) {
			return false
		}
	}
	return known && err == nil && !f.legacy && f.memory == f.first &&
		ins.x86RIPMemoryRead.source == f.first && ins.x86RIPMemoryRead.width == int64(f.memoryBytes)
}

func x86RawResultLiteralForm(ins Instr, arch string) bool {
	return x86RawVectorMoveLiteralSource(ins, arch) || x86RawIntegerMinMaxLiteralForm(ins, arch) ||
		x86RawTernaryLogicLiteralForm(ins, arch) ||
		x86RawBroadcastLiteralForm(ins, arch) || x86RawLogicalLiteralForm(ins, arch) ||
		x86RawByteShiftLiteralForm(ins, arch) || x86RawIntegerCompareLiteralForm(ins, arch) ||
		x86RawArithmeticLiteralForm(ins, arch) || x86RawFloatCompareLiteralForm(ins, arch) ||
		x86RawBinaryFloatLiteralForm(ins, arch) || x86RawFMA3LiteralForm(ins, arch) ||
		x86RawPackedAbsLiteralForm(ins, arch) || x86RawCOMILiteralForm(ins, arch) || x86RawRoundLiteralForm(ins, arch)
}

// This bounded source uses the ordinary typed family byte effects. It does
// not join the conditional native-read route or waive raw RET's separately
// checked frame, memory and continuation contracts. Other raw families retain
// their own consumers. Declaration-only queries acquire no literal permission.
func (c *amd64Ctx) checkRawLiteralResults() (bool, error) {
	fn, arch := c.fpScalarSource, c.goarch
	selected := false
	for _, ins := range fn.Instrs {
		selected = selected || x86RawResultLiteralForm(ins, arch)
	}
	if !selected {
		return false, nil
	}
	fail := func() (bool, error) {
		return true, fmt.Errorf("%w: raw literal requires its complete source and independent return contract", ErrProbeNeedsContext)
	}
	if fn.FrameSize != 0 || len(fn.X86RawText) != 0 || fn.x86SourceStack != nil ||
		fn.x86FixedLocal != nil || fn.x86DirectTailRoot != nil || fn.x86ContinuationFlow != nil ||
		fn.x86BoolCalls != nil || fn.x86RawReplay == nil {
		return fail()
	}
	if err := fn.x86RawReplay.validate(fn, arch); err != nil {
		return true, err
	}
	hasReturn := false
	for _, ins := range fn.Instrs {
		if form := ins.x86RawNearReturn; form != nil {
			if ins.Op != OpRET || !form.nativeWidth || form.cleanup != 0 {
				return fail()
			}
			hasReturn = true
		} else if !x86RawResultLiteralForm(ins, arch) && !x86ResultNamedPredicateInstruction(ins) {
			return fail()
		}
	}
	if !hasReturn {
		return fail()
	}
	transfer := func(_ int, ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) bool {
		state.loweredStaticReads = c.fpScalarData
		defer func() { state.loweredStaticReads = nil }()
		if accepted, known := x86ResultRawVectorMoveLiteralStep(ins, state, owned, resultOffset, arch); known {
			return accepted
		}
		if x86RawBroadcastLiteralForm(ins, arch) {
			accepted, _ := x86ResultBroadcastInputs(ins, state, owned, arch, false, true)
			return accepted
		}
		return x86ScalarFPResultTransfer(ins, state, owned, resultOffset, arch)
	}
	return true, checkX86ABI0ResultInitializationAtSource(fn, c.sig, arch, transfer, true)
}
