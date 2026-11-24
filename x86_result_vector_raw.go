package plan9asm

import "reflect"

// Consolidated raw-decoding identity, source-binding and replay-requirement
// predicates for x86 vector result families. None of these grant standalone,
// caller, frame, memory-backing or native-entry permissions.

// A typed family must validate the opcode and operands before using this
// original-source identity check. It grants no standalone or native entry role.
func x86RawOrdinaryVectorSource(ins Instr, arch string) bool {
	return x86RawOrdinaryVectorSourceAt(ins, arch, 0)
}

// Validate the complete original identity before selecting the typed data
// operand. An immediate-first family must not rewrite operands to borrow the
// first-data grammar, or leave its selector outside the original identity.
func x86RawOrdinaryVectorSourceAt(ins Instr, arch string, sourceIndex int) bool {
	if sourceIndex < 0 || sourceIndex >= len(ins.Args) || ins.x86SourceRaw == nil ||
		ins.x86SourceRaw.op != ins.Op || !reflect.DeepEqual(ins.x86SourceRaw.args, ins.Args) ||
		ins.x86SourceRaw.vectorBytes != ins.x86VectorBytes ||
		ins.x86SourceRaw.addressBits != ins.x86AddressBits ||
		ins.x86RawNearReturn != nil || ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride ||
		ins.x86SegmentPrefix != 0 || ins.x86RIPLiteral || ins.x86NumericalRead != nil {
		return false
	}
	source := ins.Args[sourceIndex]
	return source.Kind == OpReg || source.Kind == OpMem && source.Mem.Sym == "" &&
		source.Mem.Segment == "" && x86OrdinaryNativeMemoryOperand(source, arch)
}

func x86RawIFMASource(ins Instr, arch string) bool {
	_, known, err := x86IFMAProperties(ins.Op, ins, arch)
	return known && err == nil && x86RawOrdinaryVectorSource(ins, arch)
}

func x86RawDwordProductResultSource(ins Instr, arch string) bool {
	form, known, err := x86DwordProductProperties(ins.Op, ins, arch)
	return known && err == nil && !form.legacy && x86RawOrdinaryVectorSource(ins, arch)
}

func x86RawIntegerMinMaxSource(ins Instr, arch string) bool {
	form, known, err := x86IntegerMinMaxProperties(ins.Op, ins, arch)
	return known && err == nil && !form.legacy && ins.x86Encoded && x86RawOrdinaryVectorSource(ins, arch)
}

func x86RawIntegerMinMaxLiteralForm(ins Instr, arch string) bool {
	if !x86RawLiteralSourceShape(ins, arch) || !x86RawReturnDecodedReadIdentity(ins) {
		return false
	}
	form, known, err := x86IntegerMinMaxProperties(ins.Op, ins, arch)
	return known && err == nil && !form.legacy && form.memory == form.first &&
		ins.x86RIPMemoryRead.source == form.first && ins.x86RIPMemoryRead.width == int64(form.memoryBytes)
}

type x86RawFMA3Encoding uint8

const (
	x86RawFMA3Absent x86RawFMA3Encoding = iota
	x86RawFMA3VEX
	x86RawFMA3EVEX
)

type x86RawFMA3Identity struct {
	arch     string
	encoding x86RawFMA3Encoding
	encoded  bool
}

func x86FMA3RawIdentity(ins Instr, arch string) x86RawFMA3Identity {
	form, known, err := amd64FMA3Properties(ins, arch)
	if !known || err != nil || form.spec.rawOnly ||
		ins.x86FMA3Encoding != x86RawFMA3VEX && ins.x86FMA3Encoding != x86RawFMA3EVEX {
		return x86RawFMA3Identity{}
	}
	return x86RawFMA3Identity{arch, ins.x86FMA3Encoding, ins.x86Encoded}
}

func x86RawFMA3EncodingSource(ins Instr, arch string) bool {
	origin := ins.x86SourceRaw
	if origin == nil {
		return false
	}
	identity := x86FMA3RawIdentity(ins, arch)
	return identity.encoding != x86RawFMA3Absent && identity.arch == arch && origin.fma3 == identity &&
		origin.op == ins.Op && origin.vectorBytes == ins.x86VectorBytes &&
		origin.addressBits == ins.x86AddressBits &&
		(reflect.DeepEqual(origin.args, ins.Args) || x86RawLiteralSourceIdentity(ins, arch))
}

func x86RawFMA3Source(ins Instr, arch string) bool {
	return x86RawFMA3EncodingSource(ins, arch) && x86RawOrdinaryVectorSource(ins, arch)
}

func x86RawFMA3LiteralForm(ins Instr, arch string) bool {
	if !x86RawFMA3EncodingSource(ins, arch) || !x86RawLiteralSourceIdentity(ins, arch) {
		return false
	}
	form, known, err := amd64FMA3Properties(ins, arch)
	return known && err == nil && !form.spec.rawOnly && form.memory == 0 &&
		ins.x86RIPMemoryRead.source == 0 && ins.x86RIPMemoryRead.width == int64(form.memoryBytes)
}

func x86FMA3PreservesPrivateSourceState(ins Instr, arch string) bool {
	return x86RawFMA3Source(ins, arch) || x86RawFMA3LiteralForm(ins, arch)
}

func x86FMA3RawReplayRequired(fn Func, arch string) bool {
	hasProducer := func(instructions []Instr) bool {
		for _, ins := range instructions {
			form, known, _ := amd64FMA3Properties(ins, arch)
			if known && !form.spec.rawOnly && (ins.x86SourceRaw != nil || ins.x86FMA3Encoding != x86RawFMA3Absent) {
				return true
			}
		}
		return false
	}
	return hasProducer(fn.Instrs) || fn.x86RawReplay != nil && hasProducer(fn.x86RawReplay.decoded)
}

type x86RawTernaryLogicIdentity struct {
	arch    string
	encoded bool
}

func x86TernaryLogicRawIdentity(ins Instr, arch string) x86RawTernaryLogicIdentity {
	form, known, err := x86TernaryLogicProperties(ins.Op, ins, arch)
	if !known || err != nil || !ins.x86Encoded || ins.x86VectorBytes != form.byteWidth {
		return x86RawTernaryLogicIdentity{}
	}
	return x86RawTernaryLogicIdentity{arch: arch, encoded: ins.x86Encoded}
}

func x86RawTernaryLogicSource(ins Instr, arch string) bool {
	_, known, err := x86TernaryLogicProperties(ins.Op, ins, arch)
	origin := ins.x86SourceRaw
	return known && err == nil && origin != nil && origin.ternaryLogic.arch == arch &&
		origin.ternaryLogic == x86TernaryLogicRawIdentity(ins, arch) &&
		x86RawOrdinaryVectorSourceAt(ins, arch, 1)
}

func x86RawTernaryLogicLiteralForm(ins Instr, arch string) bool {
	if !x86RawLiteralSourceShape(ins, arch) || !x86RawReturnDecodedReadIdentity(ins) {
		return false
	}
	form, known, err := x86TernaryLogicProperties(ins.Op, ins, arch)
	return known && err == nil && form.memory == 1 &&
		ins.x86RIPMemoryRead.source == 1 && ins.x86RIPMemoryRead.width == int64(form.memoryBytes)
}

func x86RawImmediateBlendSource(ins Instr, arch string) bool {
	f, known, err := x86ImmediateBlendProperties(ins.Op, ins, arch)
	return known && err == nil && ins.x86Encoded != f.legacy &&
		x86RawOrdinaryVectorSourceAt(ins, arch, f.source)
}

func x86RawBlendMinposSource(ins Instr, arch string) bool {
	form, known, err := x86BlendMinposProperties(ins.Op, ins, arch)
	return known && err == nil && x86RawOrdinaryVectorSourceAt(ins, arch, form.source)
}

func x86RawQwordLookupSource(ins Instr, arch string) bool {
	_, known, err := x86QwordLookupProperties(ins.Op, ins, arch)
	return known && err == nil && x86RawOrdinaryVectorSource(ins, arch)
}

func x86RawScalarReciprocalSource(ins Instr, arch string) bool {
	_, known, err := x86ScalarReciprocalProperties(ins.Op, ins, arch)
	return known && err == nil && x86RawOrdinaryVectorSource(ins, arch)
}

func x86RawFP16SqrtSource(ins Instr, arch string) bool {
	f, known, err := x86SqrtProperties(ins, arch)
	return known && err == nil && f.bits == 16 && x86RawOrdinaryVectorSource(ins, arch)
}

func x86RawFP16FMASourceForm(ins Instr, arch string) (amd64FMA3Form, bool) {
	f, known, err := amd64FMA3Properties(ins, arch)
	return f, known && err == nil && f.spec.rawOnly && x86RawOrdinaryVectorSource(ins, arch)
}

func x86RawFP16ConversionSourceForm(ins Instr, arch string) (x86FP16ConversionForm, bool) {
	f, known, err := x86FP16ConversionProperties(ins, arch)
	return f, known && err == nil && x86RawOrdinaryVectorSource(ins, arch)
}

func x86RawFP16BinarySourceForm(ins Instr, arch string) (x86FP16BinaryForm, bool) {
	f, known, err := x86FP16BinaryProperties(ins, arch)
	return f, known && err == nil && x86RawOrdinaryVectorSource(ins, arch)
}

func x86RawAlternatingFloatSource(ins Instr, arch string) bool {
	form, known, err := x86AlternatingFloatProperties(ins, arch)
	return known && err == nil && !form.legacy && x86RawOrdinaryVectorSourceAt(ins, arch, form.first)
}

func x86RawRoundLiteralForm(ins Instr, arch string) bool {
	if !x86RawLiteralSourceIdentity(ins, arch) {
		return false
	}
	form, known, err := x86RoundProperties(ins, arch)
	return known && err == nil && form.spec.vector && form.memory &&
		ins.x86RIPMemoryRead.source == 1 && ins.x86RIPMemoryRead.width == int64(form.memoryBytes)
}

type x86RawFloatMinMaxIdentity struct {
	arch          string
	encoded, evex bool
}

func x86FloatMinMaxRawIdentity(ins Instr, arch string) x86RawFloatMinMaxIdentity {
	if _, known, err := x86FloatMinMaxProperties(ins, arch); !known || err != nil {
		return x86RawFloatMinMaxIdentity{}
	}
	return x86RawFloatMinMaxIdentity{arch, ins.x86Encoded, ins.x86FloatMinMaxEVEX}
}

func x86RawFloatMinMaxEncodingSource(ins Instr, arch string) bool {
	origin := ins.x86SourceRaw
	return origin != nil && origin.floatMinMax.arch == arch &&
		origin.floatMinMax == x86FloatMinMaxRawIdentity(ins, arch) &&
		origin.op == ins.Op && (reflect.DeepEqual(origin.args, ins.Args) || x86RawLiteralSourceIdentity(ins, arch)) &&
		origin.vectorBytes == ins.x86VectorBytes && origin.addressBits == ins.x86AddressBits
}

func x86RawFloatMinMaxSource(ins Instr, arch string) bool {
	return x86RawFloatMinMaxEncodingSource(ins, arch) && x86RawOrdinaryVectorSource(ins, arch)
}

func x86FloatMinMaxPreservesSourceState(ins Instr, arch string) bool {
	return x86RawFloatMinMaxSource(ins, arch) ||
		x86RawFloatMinMaxEncodingSource(ins, arch) && x86RawBinaryFloatLiteralForm(ins, arch)
}

func x86FloatMinMaxRawReplayRequired(fn Func, arch string) bool {
	if fn.x86RawReplay == nil {
		return false
	}
	for _, ins := range fn.x86RawReplay.decoded {
		if _, known, _ := x86FloatMinMaxProperties(ins, arch); known {
			return true
		}
	}
	return false
}

type x86RawPackedReductionIdentity struct {
	arch    string
	encoded bool
}

func x86PackedReductionRawIdentity(ins Instr, arch string) x86RawPackedReductionIdentity {
	local := ins
	local.x86Encoded = true
	if _, known, err := x86PackedReductionProperties(local, arch); !known || err != nil {
		return x86RawPackedReductionIdentity{}
	}
	return x86RawPackedReductionIdentity{arch: arch, encoded: ins.x86Encoded}
}

func x86RawPackedReductionSource(ins Instr, arch string) bool {
	form, known, err := x86PackedReductionProperties(ins, arch)
	origin := ins.x86SourceRaw
	return known && err == nil && origin != nil && origin.packedReduction.arch == arch &&
		origin.packedReduction == x86PackedReductionRawIdentity(ins, arch) &&
		x86RawOrdinaryVectorSourceAt(ins, arch, form.first)
}

func x86LoweredRawPackedReductionStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	if _, known, _ := x86PackedReductionProperties(ins, arch); !known || x86ResultNamedPredicateInstruction(ins) {
		return false, false
	}
	if !x86RawPackedReductionSource(ins, arch) {
		return false, true
	}
	return x86ResultTypedVectorEffectStep(ins, state, owned, arch, true, true)
}

type x86RawPackedDotEncoding uint8

const (
	x86RawPackedDotAbsent x86RawPackedDotEncoding = iota
	x86RawPackedDotVEX
	x86RawPackedDotEVEX
)

type x86RawPackedDotIdentity struct {
	arch     string
	encoding x86RawPackedDotEncoding
	encoded  bool
}

func x86PackedDotRawIdentity(ins Instr, arch string) x86RawPackedDotIdentity {
	if _, known, err := x86PackedDotProperties(ins.Op, ins, arch); !known || err != nil ||
		ins.x86PackedDotEncoding != x86RawPackedDotVEX && ins.x86PackedDotEncoding != x86RawPackedDotEVEX {
		return x86RawPackedDotIdentity{}
	}
	return x86RawPackedDotIdentity{arch, ins.x86PackedDotEncoding, ins.x86Encoded}
}

func x86RawPackedDotSource(ins Instr, arch string) bool {
	form, known, err := x86PackedDotProperties(ins.Op, ins, arch)
	return known && err == nil && ins.x86SourceRaw != nil &&
		ins.x86SourceRaw.packedDot.arch == arch &&
		ins.x86SourceRaw.packedDot == x86PackedDotRawIdentity(ins, arch) &&
		x86Mode32VectorRegisterContext(ins, arch) == nil &&
		x86RawOrdinaryVectorSourceAt(ins, arch, form.first)
}

func x86PackedDotRawReplayRequired(fn Func, arch string) bool {
	if fn.x86RawReplay != nil {
		for _, ins := range fn.x86RawReplay.decoded {
			if _, known, _ := x86PackedDotProperties(ins.Op, ins, arch); known {
				return true
			}
		}
	}
	return false
}

type x86RawNamedHalfIdentity struct {
	arch     string
	encoding x86RawNamedHalfEncoding
	encoded  bool
}

func x86NamedHalfRawIdentity(ins Instr, arch string) x86RawNamedHalfIdentity {
	_, known, err := x86NamedHalfProperties(ins.Op, ins, arch)
	if !known || err != nil || ins.x86Encoded ||
		ins.x86NamedHalfEncoding != x86RawNamedHalfVEX && ins.x86NamedHalfEncoding != x86RawNamedHalfEVEX {
		return x86RawNamedHalfIdentity{}
	}
	return x86RawNamedHalfIdentity{arch, ins.x86NamedHalfEncoding, ins.x86Encoded}
}

func x86RawNamedHalfSource(ins Instr, arch string) bool {
	f, known, err := x86NamedHalfProperties(ins.Op, ins, arch)
	identity := x86NamedHalfRawIdentity(ins, arch)
	if !known || err != nil || identity.encoding == x86RawNamedHalfAbsent || ins.x86SourceRaw == nil ||
		ins.x86SourceRaw.namedHalf != identity || !x86RawOrdinaryVectorSourceAt(ins, arch, f.source) {
		return false
	}
	return f.memory != f.destination || x86RawOrdinaryVectorSourceAt(ins, arch, f.destination)
}

func x86NamedHalfRawReplayRequired(fn Func, arch string) bool {
	hasProducer := func(instructions []Instr) bool {
		for _, ins := range instructions {
			if _, known, _ := x86NamedHalfProperties(ins.Op, ins, arch); known &&
				(ins.x86SourceRaw != nil || ins.x86NamedHalfEncoding != x86RawNamedHalfAbsent) {
				return true
			}
		}
		return false
	}
	return hasProducer(fn.Instrs) || fn.x86RawReplay != nil && hasProducer(fn.x86RawReplay.decoded)
}

type x86RawPackedPrecisionIdentity struct {
	arch          string
	encoded, evex bool
}

func x86PackedPrecisionRawIdentity(ins Instr, arch string) x86RawPackedPrecisionIdentity {
	if _, known, err := x86PackedPrecisionProperties(ins.Op, ins, arch); !known || err != nil {
		return x86RawPackedPrecisionIdentity{}
	}
	return x86RawPackedPrecisionIdentity{arch, ins.x86Encoded, ins.x86PackedPrecisionEVEX}
}

func x86RawPackedPrecisionSource(ins Instr, arch string) bool {
	origin := ins.x86SourceRaw
	return origin != nil && ins.x86Encoded && origin.packedPrecision.arch == arch &&
		origin.packedPrecision == x86PackedPrecisionRawIdentity(ins, arch) && x86RawOrdinaryVectorSource(ins, arch)
}

func x86PackedPrecisionRawReplayRequired(fn Func, arch string) bool {
	if fn.x86RawReplay != nil {
		for _, ins := range fn.x86RawReplay.decoded {
			if _, known, _ := x86PackedPrecisionProperties(ins.Op, ins, arch); known {
				return true
			}
		}
	}
	return false
}

type x86RawScalarPrecisionIdentity struct {
	arch          string
	encoded, evex bool
}

func x86ScalarPrecisionRawIdentity(ins Instr, arch string) x86RawScalarPrecisionIdentity {
	if _, known, err := x86ScalarPrecisionProperties(ins.Op, ins, arch); !known || err != nil {
		return x86RawScalarPrecisionIdentity{}
	}
	return x86RawScalarPrecisionIdentity{arch, ins.x86Encoded, ins.x86ScalarPrecisionEVEX}
}

func x86RawScalarPrecisionSource(ins Instr, arch string) bool {
	origin := ins.x86SourceRaw
	return origin != nil && ins.x86Encoded && origin.scalarPrecision.arch == arch &&
		origin.scalarPrecision == x86ScalarPrecisionRawIdentity(ins, arch) &&
		x86RawOrdinaryVectorSource(ins, arch)
}

func x86ScalarPrecisionRawReplayRequired(fn Func, arch string) bool {
	if fn.x86RawReplay == nil {
		return false
	}
	for _, ins := range fn.x86RawReplay.decoded {
		if _, known, _ := x86ScalarPrecisionProperties(ins.Op, ins, arch); known {
			return true
		}
	}
	return false
}

type x86RawPermute128Identity struct {
	arch    string
	vex     bool
	encoded bool
}

func x86Permute128RawIdentity(ins Instr, arch string) x86RawPermute128Identity {
	if _, known, err := x86Permute128Properties(ins.Op, ins, arch); !known || err != nil ||
		!ins.x86Permute128VEX || !ins.x86Encoded || ins.x86VectorBytes != 32 {
		return x86RawPermute128Identity{}
	}
	return x86RawPermute128Identity{arch, true, true}
}

func x86RawPermute128Source(ins Instr, arch string) bool {
	form, known, err := x86Permute128Properties(ins.Op, ins, arch)
	return known && err == nil && ins.x86SourceRaw != nil &&
		ins.x86SourceRaw.permute128.arch == arch &&
		ins.x86SourceRaw.permute128 == x86Permute128RawIdentity(ins, arch) &&
		x86RawOrdinaryVectorSourceAt(ins, arch, form.first)
}

func x86Permute128RawReplayRequired(fn Func, arch string) bool {
	if fn.x86RawReplay != nil {
		for _, ins := range fn.x86RawReplay.decoded {
			if _, known, _ := x86Permute128Properties(ins.Op, ins, arch); known {
				return true
			}
		}
	}
	return false
}

type x86RawPackedConversionIdentity struct {
	arch               string
	encoded, evex, mmx bool
}

func x86PackedConversionRawIdentity(ins Instr, arch string) x86RawPackedConversionIdentity {
	_, signed, signedErr := x86SignedPackedFloatProperties(ins, arch)
	_, numeric, numericErr := x86PackedConversionProperties(ins, arch)
	if !signed && !numeric || signed && signedErr != nil || numeric && numericErr != nil {
		return x86RawPackedConversionIdentity{}
	}
	return x86RawPackedConversionIdentity{
		arch: arch, encoded: ins.x86Encoded,
		evex: ins.x86PackedNumericEVEX, mmx: ins.x86MMXSourceConversion,
	}
}

func x86RawPackedConversionSource(ins Instr, arch string) bool {
	origin := ins.x86SourceRaw
	if origin == nil || origin.packedConversion.arch != arch ||
		origin.packedConversion != x86PackedConversionRawIdentity(ins, arch) ||
		!x86RawOrdinaryVectorSource(ins, arch) {
		return false
	}
	if form, known, err := x86SignedPackedFloatProperties(ins, arch); known {
		return err == nil && !form.mmx
	}
	form, known, err := x86PackedConversionProperties(ins, arch)
	return known && err == nil && !form.mmx
}
