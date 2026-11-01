package plan9asm

import (
	"fmt"
	"sort"
	"strings"
)

const featureAttrBase = 200

type featureAttrRegistry struct {
	order []string
	refs  map[string]string
}

func newFeatureAttrRegistry() *featureAttrRegistry {
	return &featureAttrRegistry{refs: make(map[string]string)}
}

func (r *featureAttrRegistry) ref(features string) string {
	if features == "" {
		return ""
	}
	if ref, ok := r.refs[features]; ok {
		return ref
	}
	ref := fmt.Sprintf("#%d", featureAttrBase+len(r.order))
	r.order = append(r.order, features)
	r.refs[features] = ref
	return ref
}

func (r *featureAttrRegistry) emit(b *strings.Builder) {
	if len(r.order) == 0 {
		return
	}
	for _, features := range r.order {
		fmt.Fprintf(b, "attributes %s = { \"target-features\"=%q }\n", r.refs[features], features)
	}
	b.WriteString("\n")
}

func inferFuncTargetFeatures(arch Arch, fn Func) string {
	return inferFuncTargetFeaturesForGOARCH(arch, "", fn)
}

func inferFuncTargetFeaturesForGOARCH(arch Arch, goarch string, fn Func) string {
	var featureSet []string
	add := func(features ...string) {
		for _, feature := range features {
			if feature == "" {
				continue
			}
			exists := false
			for _, v := range featureSet {
				if v == feature {
					exists = true
					break
				}
			}
			if !exists {
				featureSet = append(featureSet, feature)
			}
		}
	}

	for _, ins := range fn.Instrs {
		op := strings.ToUpper(string(ins.Op))
		switch arch {
		case ArchAMD64:
			moveArch := goarch
			if moveArch == "" {
				moveArch = "amd64"
			}
			// These disjoint typed families completely own their feature needs.
			// Only valid forms bypass unrelated probes; errors keep the original
			// raw/special-opcode fallback below.
			if form, known, err := x86PackedLogicalProperties(ins, goarch); known && err == nil {
				if form.legacy && !form.mmx && form.memory >= 0 && ins.Args[form.memory].Kind != OpFP {
					// Only the validated native opcode needs the private XMM carrier.
					if form.spec.encoding == x86PackedLogicalLegacyFP && form.spec.laneBits == 32 {
						add("+sse")
					} else {
						add("+sse2")
					}
				}
				continue
			}
			if form, known, err := amd64PackedVectorMoveProperties(ins, moveArch); known && err == nil {
				if form.spec.aligned && form.memory >= 0 && !form.undefinedOpcode() {
					if form.nativeEVEX(ins) {
						add("+avx512f")
						if form.byteWidth < 64 {
							add("+avx512vl")
						}
					} else {
						add("+avx")
					}
				}
				continue
			}
			if x86BaselineGPFeatureInstruction(Op(op), &ins, moveArch) {
				continue
			}
			if _, terminal, err := x86UndefinedTrapProperties(ins.Op, ins, moveArch); terminal && err == nil {
				continue // Exact UD2 does not execute this source opcode or require its input ISA.
			}
			if form, known, err := x86FourSourceProperties(ins.Op, ins, moveArch); known && err == nil {
				add("+avx512f") // Exact physical carriers, including scalar SS and isolated mode32.
				if form.spec.mode == amd64FourSourceFMA {
					add("+avx5124fmaps")
				} else {
					add("+avx5124vnniw")
				}
			}
			if form, known, err := x86ScalarPrecisionProperties(ins.Op, ins, moveArch); known && err == nil {
				switch {
				case form.spec.legacy:
					add("+sse2") // Both scalar precision conversions are SSE2, including CVTSS2SD.
				case x86ScalarPrecisionNativeEVEX(ins, form):
					add("+avx512f") // Scalar EVEX needs F, not the packed narrow VL feature.
				default:
					add("+avx")
				}
			}
			if form, known, err := x86PackedPrecisionProperties(ins.Op, ins, moveArch); known && err == nil {
				switch {
				case form.spec.legacy:
					add("+sse2")
				case form.evex:
					add("+avx512f")
					if form.shape.sourceBytes < 64 && form.shape.destinationBytes < 64 {
						add("+avx512vl")
					}
				default:
					add("+avx")
				}
			}
			if form, known, err := x86NamedHalfProperties(ins.Op, ins, moveArch); known && err == nil {
				if form.evex {
					add("+avx512f")
					if form.sourceBytes < 64 && form.destinationBytes < 64 {
						add("+avx512vl")
					}
				} else {
					add("+avx", "+f16c")
				}
			}
			if _, known, err := x86UnsignedIntegerFloatProperties(ins, moveArch); known && err == nil {
				add("+avx512f") // Scalar unsigned EVEX needs F, not packed narrow VL.
			}
			if _, known, err := x86ExplicitMaskMoveProperties(ins.Op, ins, moveArch); known && err == nil {
				if strings.HasPrefix(op, "VPMASK") {
					add("+avx2")
				} else {
					add("+avx")
				}
			}
			if form, known, err := x86PackedReductionProperties(ins, moveArch); known && err == nil {
				if form.dot {
					add("+sse4.1")
				} else if form.legacy {
					add("+sse3")
				}
				if !form.legacy {
					add("+avx")
				}
			}
			if form, known, err := x86UnalignedLoadProperties(ins.Op, ins, moveArch); known && err == nil {
				if form.spec.vector {
					add("+avx")
				} else {
					add("+sse3")
				}
			}
			if form, known, err := x86DuplicateMoveProperties(ins.Op, ins, moveArch); known && err == nil &&
				form.legacy && form.spec.laneBytes == 4 && form.memory >= 0 {
				add("+sse3") // Only the original aligned legacy opcode needs a native carrier.
			}
			if form, known, err := x86AlternatingFloatProperties(ins, moveArch); known && err == nil &&
				form.legacy && form.memory >= 0 && ins.Args[form.memory].Kind != OpFP {
				add("+sse3") // The original ADDSUB memory opcode requires its native XMM carrier.
			}
			if form, known, err := amd64FMA3Properties(ins, moveArch); known && err == nil && !form.spec.rawOnly {
				if x86FMA3NativeEVEX(ins, form) {
					add("+avx512f")
					if !form.spec.scalar && form.byteWidth < 64 {
						add("+avx512vl")
					}
				} else {
					add("+avx", "+fma")
				}
			}
			if form, known, err := x86FloatingHelperProperties(ins, moveArch); known && err == nil {
				add("+avx512f")
				if form.spec.dq {
					add("+avx512dq")
				}
				if !form.spec.scalar && form.byteWidth < 64 {
					add("+avx512vl")
				}
				if form.spec.estimate14 {
					continue // This complete shape already supplies the precise F/VL requirement.
				}
			}
			if form, known, err := x86SqrtProperties(ins, moveArch); known && err == nil {
				switch {
				case x86SqrtNativeEVEX(ins, form):
					add("+avx512f")
					if !form.scalar && form.byteWidth < 64 {
						add("+avx512vl")
					}
				case !form.legacy:
					add("+avx")
				case form.bits == 64:
					add("+sse2")
				default:
					add("+sse")
				}
			}
			if _, known, err := x86ByteShuffleProperties(ins.Op, ins, moveArch); known && err == nil {
				// Every width lowers through the SSSE3 intrinsic, including
				// an isolated .Z function with no unsuffixed sibling.
				add("+ssse3")
			}
			if form, known, err := x86PackedAbsSignProperties(ins.Op, ins, moveArch); known && err == nil {
				// Each original form owns its minimum ISA; an unrelated MOVOU
				// must not accidentally supply an i386 native XMM carrier.
				switch {
				case form.legacy:
					add("+sse2", "+ssse3")
				case form.evex(ins):
					add("+avx512f")
					if form.spec.laneBits < 32 {
						add("+avx512bw")
					}
					if form.byteWidth < 64 {
						add("+avx512vl")
					}
				case form.byteWidth == 32:
					add("+avx2")
				default:
					add("+avx")
				}
			}
			if form, known, err := x86BlendMinposProperties(ins.Op, ins, moveArch); known && err == nil {
				switch {
				case form.legacy:
					add("+sse2", "+sse4.1")
				case !form.minimum && form.laneBits == 8 && form.byteWidth == 32:
					add("+avx2")
				default:
					add("+avx")
				}
			}
			if form, known, err := x86ImmediateBlendProperties(ins.Op, ins, moveArch); known && err == nil {
				switch {
				case form.legacy:
					add("+sse2", "+sse4.1")
				case ins.Op == "VPBLENDD" || ins.Op == "VPBLENDW" && form.byteWidth == 32:
					add("+avx2")
				default:
					add("+avx")
				}
			}
			if form, known, err := x86FloatMinMaxProperties(ins, moveArch); known && err == nil {
				switch {
				case x86FloatMinMaxNativeEVEX(ins, form):
					add("+avx512f")
					if !form.scalar && form.byteWidth < 64 {
						add("+avx512vl")
					}
				case !form.legacy:
					add("+avx")
				case form.bits == 64:
					add("+sse2")
				default:
					add("+sse")
				}
			}
			if form, known, err := x86PackedAlignProperties(ins.Op, ins, moveArch); known && err == nil &&
				form.legacy && form.memory >= 0 && ins.Args[form.memory].Kind != OpFP {
				add("+sse2", "+ssse3") // The isolated original PALIGNR m128 needs its physical carrier.
			}
			if form, known, err := x86VectorTestProperties(ins.Op, ins, moveArch); known && err == nil &&
				ins.Args[0].Kind != OpReg && ins.Args[0].Kind != OpFP {
				if form.vector {
					add("+avx")
				} else {
					add("+sse4.1")
				}
			}
			if form, known, err := x86MoveMaskProperties(ins.Op, ins, moveArch); known && err == nil &&
				moveArch == "386" && form.floatingLaneBits == 0 && form.byteWidth >= 16 {
				// Both packed byte-mask widths lower through the SSE2 i128
				// intrinsic, even when no sibling instruction enables SSE2.
				add("+sse2")
			}
			if form, known, err := x86COMIProperties(ins, moveArch); known && err == nil {
				if form.evex {
					add("+avx512f")
				} else if form.spec.vector {
					add("+avx")
				} else if form.spec.bits == 64 {
					add("+sse2")
				} else {
					add("+sse")
				}
			}
			if spec, known, err := x86ImplicitMaskMoveProperties(ins.Op, ins, moveArch); known && err == nil {
				switch {
				case spec.byteWidth == 8:
					add("+mmx")
					add("+sse")
				case spec.vector:
					add("+avx")
				default:
					add("+sse2")
				}
			}
			if form, known, err := x86NonTemporalVectorProperties(ins.Op, ins, moveArch); known && err == nil && !form.trap {
				switch {
				case !form.spec.vector && form.spec.load:
					add("+sse4.1")
				case !form.spec.vector && form.spec.native == "movntps":
					add("+sse")
				case !form.spec.vector:
					add("+sse2")
				case form.move.nativeEVEX(ins):
					add("+avx512f")
					if form.move.byteWidth < 64 {
						add("+avx512vl")
					}
				case form.spec.load && form.move.byteWidth == 32:
					add("+avx2")
				default:
					add("+avx")
				}
			}
			if form, known, err := x86LegacyPackedMoveProperties(ins.Op, ins, moveArch); known && err == nil &&
				form.memory >= 0 && ins.Args[form.memory].Kind != OpFP {
				// Exact native whole128 opcodes need XMM registers on i386.
				// PS moves are SSE1; a sibling MOVOU must not be needed to
				// accidentally supply the register class to an isolated move.
				if op == "MOVUPS" || op == "MOVAPS" {
					add("+sse")
				} else {
					add("+sse2")
				}
			}
			if form, known, err := x86HorizontalIntegerProperties(ins, goarch); known && err == nil &&
				!form.spec.vector && !form.mmx && form.memory >= 0 && ins.Args[form.memory].Kind != OpFP {
				// The single original legacy m128 opcode needs its physical
				// SSSE3 carrier on i386 as well. Portable register/VEX arithmetic
				// does not acquire a native ISA or caller permission.
				add("+sse2", "+ssse3")
			}
			if form, known, err := x86ImmediateShuffleProperties(ins, goarch); known && err == nil &&
				form.spec.legacy && !form.spec.mmx && form.memory >= 0 && form.source.Kind != OpFP {
				// Only this validated single native SSE2 memory instruction
				// needs its private XMM carrier, including the physical i386 path.
				add("+sse2")
			}
			if form, known, err := x86PackedFloatShuffleProperties(ins.Op, ins, moveArch); known && err == nil &&
				form.legacy && form.memory >= 0 && ins.Args[form.memory].Kind != OpFP {
				if form.bits == 32 {
					add("+sse")
				} else {
					add("+sse2")
				}
			}
			if form, known, err := x86IntegerMinMaxProperties(ins.Op, ins, moveArch); known && err == nil &&
				form.legacy && form.memory >= 0 && ins.Args[form.memory].Kind != OpFP {
				add("+sse2")
				if form.spec.mapNumber == 2 {
					add("+sse4.1")
				}
			}
			if form, known, err := x86PackedIntegerCompareProperties(ins.Op, ins, goarch); known && err == nil && form.legacy && !form.mmx && form.memory >= 0 && form.source.Kind != OpFP {
				add("+sse2")
				if form.spec.laneBits == 64 {
					if form.spec.greater {
						add("+sse4.2")
					} else {
						add("+sse4.1")
					}
				}
			}
			if form, known, err := x86ScalarFloatIntegerProperties(ins, goarch); known && err == nil {
				if form.evex {
					add("+avx512f")
				} else if form.spec.vector {
					add("+avx")
				} else if form.spec.inputBits == 32 {
					add("+sse")
				} else {
					add("+sse2")
				}
			}
			// Only the validated native compare form gets its private ISA.
			// This grants no caller memory or physical register permission.
			if form, known, err := x86FloatCompareProperties(ins, goarch); known && err == nil {
				if form.legacy {
					if form.bits == 32 {
						add("+sse")
					} else {
						add("+sse2")
					}
				} else if form.maskResult {
					add("+avx512f")
					if !form.scalar && form.byteWidth < 64 {
						add("+avx512vl")
					}
				} else {
					add("+avx")
				}
			}
			if f, known, err := x86PackedConversionProperties(ins, goarch); known && err == nil {
				if f.evex {
					add("+avx512f")
					if f.spec.sourceBits == 64 && f.spec.sourceKind != amd64PackedNumericFloat ||
						f.spec.destinationBits == 64 && f.spec.destinationKind != amd64PackedNumericFloat {
						add("+avx512dq")
					}
					if f.shape.sourceBytes < 64 && f.shape.destinationBytes < 64 {
						add("+avx512vl")
					}
				} else if f.spec.legacy {
					add("+sse2")
				} else {
					add("+avx")
				}
			}
			if f, known, err := x86SignedPackedFloatProperties(ins, goarch); known && err == nil {
				if f.spec.legacy {
					if f.mmx {
						add("+mmx", "+sse")
					}
					if !f.mmx || f.spec.bits == 64 {
						add("+sse2")
					}
				} else if f.evex {
					add("+avx512f")
					if f.byteWidth < 64 {
						add("+avx512vl")
					}
				} else {
					add("+avx")
				}
			}
			if form, known, err := x86LegacyIntegerArithmeticProperties(ins.Op, ins, goarch); known && err == nil && form.legacy && !form.mmx && form.memory >= 0 && form.source.Kind != OpFP {
				add("+sse2")
			}
			if form, known, err := x86PackedPhysicalProperties(ins.Op, ins, goarch, ""); known && err == nil && form.legacy && !form.mmx && form.memory >= 0 && ins.Args[form.memory].Kind != OpFP {
				add("+sse2")
				if form.spec.family == x86PackedMultiplyAdd && form.spec.inputBits == 8 ||
					form.spec.family == x86PackedWordProduct && form.spec.mode == amd64PackedWordMultiplyRoundedSignedHigh {
					add("+ssse3")
				}
				if form.spec.family == x86PackedDwordProduct && form.spec.signed {
					add("+sse4.1")
				}
			}
			if form, known, err := x86PackedLowMultiplyProperties(ins.Op, ins, goarch); known && err == nil && form.legacy && form.memory >= 0 {
				add("+sse2", "+sse4.1")
			}
			if form, known, err := x86PackedUnpackProperties(ins, moveArch); known && err == nil &&
				form.legacy && !form.mmx && form.memory >= 0 && form.source.Kind != OpFP {
				// The original memory opcode needs its own XMM carrier on
				// i386; no sibling may supply that native register class.
				if form.spec.grammar.encoding == x86PackedLogicalLegacyFP && form.spec.laneBits == 32 {
					add("+sse")
				} else {
					add("+sse2")
				}
			}
			if form, known, err := x86PackedNarrowProperties(ins, goarch); known && err == nil && form.legacy && !form.mmx && form.memory >= 0 && ins.Args[form.memory].Kind != OpFP {
				add("+sse2")
				if op == "PACKUSDW" {
					add("+sse4.1")
				}
			}
			if form, known, err := x86PackedSADProperties(ins, goarch); known && err == nil &&
				form.legacy && form.memory >= 0 && ins.Args[form.memory].Kind != OpFP {
				// The exact legacy m128 opcode needs an XMM carrier on i386.
				// In particular PSADBW cannot borrow SSE2 from a sibling move.
				add("+sse2")
				if form.spec.kind == amd64PackedSADMultiple {
					add("+sse4.1")
				}
			}
			if goarch == "386" {
				// The signed default-rounding scalar bridge must use MXCSR,
				// rather than LLVM's default i386 x87 conversion. Admit only
				// its validated source form and private SSE result register.
				if form, known, err := x86SignedIntegerFloatProperties(ins, goarch); known && err == nil && form.rounding == "" {
					if form.spec.resultBits == 32 {
						add("+sse")
					} else {
						add("+sse2")
					}
				}
				// Only actually validated native legacy m128 forms need an
				// XMM constraint for their exact original SSE opcode bridge.
				switch x86LegacyPackedFloatingNativeMemoryBits(ins, goarch) {
				case 32:
					add("+sse")
				case 64:
					add("+sse2")
				}
				// Default i386 floating legalization otherwise uses x87, whose
				// control/status state is not the source instruction's MXCSR.
				// Only validated dynamic MUL/DIV forms get this private SSE
				// baseline; software ER, malformed and high-bank forms do not.
				if form, known, err := x86FloatMulDivProperties(ins, goarch); known && err == nil && form.rounding == "" {
					if form.bits == 32 {
						add("+sse")
					} else {
						add("+sse2")
					}
				}
			}
			if form, recognized, err := x86PackedShiftProperties(ins.Op, ins, goarch); recognized && err == nil && x86PackedShiftHasNativeCount(form) {
				add("+sse2")
			}
			switch {
			case isAMD64RawFP16Op(op):
				add("+avx512fp16")
				if ins.x86VectorBytes == 16 || ins.x86VectorBytes == 32 {
					add("+avx512vl")
				}
				base := strings.SplitN(op, ".", 2)[0]
				if strings.HasSuffix(base, "PH") && len(ins.Args) != 0 {
					destination := ins.Args[len(ins.Args)-1]
					width := amd64VectorByteWidth(destination.Reg)
					if width == 16 || width == 32 {
						add("+avx512vl")
					}
				}
			case strings.HasPrefix(op, "VDPBF16PS"):
				add("+avx512f", "+avx512bf16")
				if len(ins.Args) != 0 && amd64VectorByteWidth(ins.Args[len(ins.Args)-1].Reg) < 64 {
					add("+avx512vl")
				}
			case strings.HasPrefix(op, "VCVTNEPS2BF16"):
				add("+avx512f", "+avx512bf16")
				if strings.HasPrefix(op, "VCVTNEPS2BF16X") || strings.HasPrefix(op, "VCVTNEPS2BF16Y") {
					add("+avx512vl")
				}
			case op == "XBEGIN" || op == "XABORT" || op == "XEND" || op == "XTEST":
				add("+rtm")
			case op == "RDPKRU" || op == "WRPKRU":
				add("+pku")
			case op == "UMONITOR" || op == "UMWAIT" || op == "TPAUSE":
				add("+waitpkg")
			case op == "XSETBV":
				add("+xsave")
			case op == "CLDEMOTE":
				add("+cldemote")
			case op == "INVPCID":
				add("+invpcid")
			case strings.Contains(op, "FSBASE") || strings.Contains(op, "GSBASE"):
				add("+fsgsbase")
			case strings.HasPrefix(op, "FXSAVE") || strings.HasPrefix(op, "FXRSTOR"):
				add("+fxsr")
			case strings.HasPrefix(op, "XSAVEOPT"):
				add("+xsave", "+xsaveopt")
			case strings.HasPrefix(op, "XSAVEC"):
				add("+xsave", "+xsavec")
			case strings.HasPrefix(op, "XSAVES") || strings.HasPrefix(op, "XRSTORS"):
				add("+xsave", "+xsaves")
			case strings.HasPrefix(op, "XSAVE") || strings.HasPrefix(op, "XRSTOR"):
				add("+xsave")
			case strings.HasPrefix(op, "VPCMPESTR") || strings.HasPrefix(op, "VPCMPISTR"):
				add("+avx", "+sse4.2")
			case strings.HasPrefix(op, "PCMPESTR") || strings.HasPrefix(op, "PCMPISTR"):
				add("+sse4.2")
			case strings.HasPrefix(op, "VEXP2") || strings.HasPrefix(op, "VRCP28") || strings.HasPrefix(op, "VRSQRT28"):
				// LLVM 22 removed the avx512er feature flag and target intrinsics,
				// but its x86 assembler still supports these encodings. AVX512F
				// supplies the Z/K register classes used by the inline assembly.
				add("+avx512f")
			case strings.HasPrefix(op, "VRCP14") || strings.HasPrefix(op, "VRSQRT14"):
				add("+avx512f", "+avx512vl")
			case op == "VMPSADBW":
				add("+avx", "+sse4.1")
				for _, arg := range ins.Args {
					if arg.Kind == OpReg && isAMD64YReg(arg.Reg) {
						add("+avx2")
					}
				}
			case op == "MPSADBW":
				add("+sse4.1")
			case strings.HasPrefix(op, "RDRAND"):
				add("+rdrnd")
			case strings.HasPrefix(op, "LZCNT"):
				add("+lzcnt")
			case strings.HasPrefix(op, "ADCX") || strings.HasPrefix(op, "ADOX"):
				add("+adx")
			case strings.HasPrefix(op, "RDSEED"):
				add("+rdseed")
			case op == "CLFLUSHOPT":
				add("+clflushopt")
			case op == "CLWB":
				add("+clwb")
			case op == "RDPID":
				add("+rdpid")
			case op == "CMPXCHG16B":
				add("+cx16")
			case strings.HasPrefix(op, "BLS"):
				add("+bmi")
			case op == "ANDNL" || op == "ANDNQ":
				add("+bmi")
			case strings.HasPrefix(op, "BEXTR"):
				add("+bmi")
			case strings.HasPrefix(op, "MULX") || strings.HasPrefix(op, "RORX") || strings.HasPrefix(op, "SHLX") || strings.HasPrefix(op, "SHRX") || strings.HasPrefix(op, "SARX") || strings.HasPrefix(op, "PDEP") || strings.HasPrefix(op, "PEXT") || strings.HasPrefix(op, "BZHI"):
				add("+bmi2")
			case op == "RCPPS" || op == "RSQRTPS" || op == "RCPSS" || op == "RSQRTSS":
				add("+sse")
			case goarch == "386" && (op == "CVTPL2PS" || op == "CVTPS2PL" || op == "CVTTPS2PL"):
				// The Go names share SSE2 X forms and older SSE MMX forms.
				// LLVM 22 cannot legalize the SSE2 conversion intrinsic for an
				// i386 function that has no +sse2 target feature.
				mmxForm := len(ins.Args) == 2 && ins.Args[0].Kind == OpReg && op == "CVTPL2PS"
				if mmxForm {
					_, mmxForm = amd64ParseMReg(ins.Args[0].Reg)
				}
				if len(ins.Args) == 2 && op != "CVTPL2PS" && ins.Args[1].Kind == OpReg {
					_, mmxForm = amd64ParseMReg(ins.Args[1].Reg)
				}
				if mmxForm {
					add("+sse")
				} else {
					add("+sse2")
				}
			case goarch == "386" && (op == "CVTPL2PD" || op == "CVTPD2PL" || op == "CVTTPD2PL"):
				add("+sse2")
			case op == "VRCPPS" || op == "VRSQRTPS" || op == "VRCPSS" || op == "VRSQRTSS":
				add("+avx", "+sse")
			case strings.HasPrefix(op, "VROUND"):
				add("+avx")
			case strings.HasPrefix(op, "ROUND"):
				add("+sse4.1")
			case goarch == "386" && (op == "MOVOU" || op == "PCMPEQB" || op == "PCMPEQL" || op == "PMOVMSKB"):
				add("+sse2")
			case strings.HasPrefix(op, "CRC32"):
				add("+crc32", "+sse4.2")
			case op == "MOVNTIL" || op == "MOVNTIQ":
				add("+sse2")
			case strings.HasPrefix(op, "MOVBE"):
				add("+movbe")
			case x86SHAEncodings[Op(op)] != 0:
				add("+sha", "+sse2")
			case op == "PCLMULQDQ" || op == "VPCLMULQDQ":
				add("+pclmul", "+sse4.1")
			case op == "AESENC" || op == "AESENCLAST" || op == "AESDEC" || op == "AESDECLAST" || op == "AESIMC" || op == "AESKEYGENASSIST" ||
				op == "VAESENC" || op == "VAESENCLAST" || op == "VAESDEC" || op == "VAESDECLAST" || op == "VAESIMC" || op == "VAESKEYGENASSIST":
				add("+aes")
			}
		case ArchARM64:
			if _, matched, err := parseARM64SVECnt(arm64ControlOp(ins), ins); matched && err == nil {
				add("+sve")
			}
			if _, matched, err := parseARM64RNDR(ins); matched && err == nil {
				add("+rand")
			}
			if op == "SMC" || op == "DCPS3" {
				add("+el3")
			}
			if op == "MSR" && len(ins.Args) == 2 && ins.Args[0].Kind == OpImm &&
				ins.Args[1].Kind == OpIdent && strings.EqualFold(ins.Args[1].Ident, "DIT") {
				add("+dit")
			}
			if op == "WORD" && len(ins.Args) == 1 && ins.Args[0].Kind == OpImm && ins.Args[0].ImmRaw == "" {
				if _, ok := decodeARM64RawSVECharacterMatch(uint32(ins.Args[0].Imm)); ok {
					add("+sve", "+sve2")
				}
				if _, ok := decodeARM64RawSVEPredicateBreak(uint32(ins.Args[0].Imm)); ok {
					add("+sve")
				}
				if decoded, ok := decodeARM64RawSVEPredicateCount(uint32(ins.Args[0].Imm)); ok {
					add("+sve")
					if arm64SVEPredicateCounterNeedsSVE2P1(decoded.Op, decoded) {
						add("+sve2p1")
					}
				}
				if _, ok := decodeARM64RawSVEPredicateIncDec(uint32(ins.Args[0].Imm)); ok {
					add("+sve")
				}
				if decoded, ok := decodeARM64RawSVEFloatMinMax(uint32(ins.Args[0].Imm)); ok {
					add("+sve")
					switch arm64SVEFloatMinMaxSpecs[decoded.Op].kind {
					case arm64SVEFloatMinMaxPairwise:
						add("+sve2")
					case arm64SVEFloatMinMaxQuadReduce:
						add("+sve2p1")
					}
				}
				if decoded, ok := decodeARM64RawSVEFloatUnary(uint32(ins.Args[0].Imm)); ok {
					add("+sve")
					if arm64SVEFloatUnarySpecs[decoded.Op].fptoint {
						add("+fptoint")
					}
				}
				if _, ok := decodeARM64RawSVEFloatCompare(uint32(ins.Args[0].Imm)); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVEIntegerCompare(uint32(ins.Args[0].Imm)); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVEPredicateLogical(uint32(ins.Args[0].Imm)); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVEPredicatePermute(uint32(ins.Args[0].Imm)); ok {
					add("+sve")
				}
				if decoded, ok := decodeARM64RawSVECompact(uint32(ins.Args[0].Imm)); ok {
					add("+sve")
					if arm64SVECompactNeedsSVE2P2(decoded) {
						add("+sve2p2")
					}
				}
				if _, ok := decodeARM64RawSVECopy(uint32(ins.Args[0].Imm)); ok {
					add("+sve")
				}
				if decoded, ok := decodeARM64RawSVEIntegerUnary(uint32(ins.Args[0].Imm)); ok {
					add("+sve")
					if arm64SVEIntegerUnarySpecs[decoded.Op].sve2 {
						add("+sve2")
					}
				}
				if decoded, ok := decodeARM64RawSVERevd(uint32(ins.Args[0].Imm)); ok {
					add("+sve", "+sve2p1")
					if arm64SVERevdNeedsSVE2P2(decoded) {
						add("+sve2p2")
					}
				}
				if decoded, ok := decodeARM64RawSVEStructuredMemory(uint32(ins.Args[0].Imm)); ok {
					add("+sve")
					if arm64SVEStructuredMemorySpecs[decoded.Op].q {
						add("+sve2p1")
					}
				}
				if decoded, ok := decodeARM64RawSVEMultiplyAccumulate(uint32(ins.Args[0].Imm)); ok {
					add("+sve")
					if arm64SVEMultiplyAccumulateNeedsSVE2(decoded) {
						add("+sve2")
					}
				}
				if _, ok := decodeARM64RawSVETernaryBitwise(uint32(ins.Args[0].Imm)); ok {
					add("+sve", "+sve2")
				}
				if decoded, ok := decodeARM64RawSVEIntegerReduction(uint32(ins.Args[0].Imm)); ok {
					add("+sve")
					if arm64SVEIntegerReductionSpecs[decoded.Op].quad {
						add("+sve2p1")
					}
				}
				if decoded, ok := decodeARM64RawSVEIntegerDot(uint32(ins.Args[0].Imm)); ok {
					add("+sve", "+sve2", arm64SVEIntegerDotFeature(decoded))
					if arm64SVEIntegerDotSpecs[decoded.Op].mixed {
						add("+i8mm")
					}
				}
				if _, ok := decodeARM64RawSVEXAR(uint32(ins.Args[0].Imm)); ok {
					add("+sve", "+sve2")
				}
				if decoded, ok := decodeARM64RawSVEExtraShift(uint32(ins.Args[0].Imm)); ok {
					add("+sve")
					if arm64SVEImmediateShiftSpecs[decoded.Op].sve2 {
						add("+sve2")
					}
				}
				if decoded, ok := decodeARM64RawSVEUnsignedLoad(uint32(ins.Args[0].Imm)); ok {
					add("+sve")
					if arm64SVEOrdinaryMemoryNeedsSVE2P1(decoded) {
						add("+sve2p1")
					}
				}
				if _, ok := decodeARM64RawSVESignedLoad(uint32(ins.Args[0].Imm)); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVEAddSubWide(uint32(ins.Args[0].Imm)); ok {
					add("+sve", "+sve2")
				}
				if decoded, ok := decodeARM64RawSVEMultiplyHigh(uint32(ins.Args[0].Imm)); ok {
					add("+sve")
					if arm64SVEMultiplyHighNeedsSVE2(decoded) {
						add("+sve2")
					}
				}
				if _, ok := decodeARM64RawSVEAddressGeneration(uint32(ins.Args[0].Imm)); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVEFloatDivideScale(uint32(ins.Args[0].Imm)); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVEFloatReciprocalStep(uint32(ins.Args[0].Imm)); ok {
					add("+sve")
				}
				if decoded, ok := decodeARM64RawSVESplice(uint32(ins.Args[0].Imm)); ok {
					add("+sve")
					if len(decoded.Args) == 3 {
						add("+sve2")
					}
				}
				if _, ok := decodeARM64RawSVEReplicateScalar(uint32(ins.Args[0].Imm)); ok {
					add("+sve")
				}
				if decoded, ok := decodeARM64RawSVEReplicateBlock(uint32(ins.Args[0].Imm)); ok {
					add("+sve")
					if arm64SVEReplicateMemorySpecs[decoded.Op].blockBytes == 32 {
						add("+f64mm")
					}
				}
				if form, ok := decodeARM64RawException(uint32(ins.Args[0].Imm)); ok {
					if form.mnemonic == "smc" {
						add("+el3")
					}
				}
				if _, ok := decodeARM64RawStreamingModeControl(uint32(ins.Args[0].Imm)); ok {
					add("+sme")
				}
				if _, ok := decodeARM64RawZAZero(uint32(ins.Args[0].Imm)); ok {
					add("+sme")
				}
				if form, ok := decodeARM64RawSMEOuterProduct(uint32(ins.Args[0].Imm)); ok {
					add("+sme", "+sve")
					if form.sourceBits == 64 {
						add("+sme-f64f64")
					}
				}
				if _, ok := decodeARM64RawSMETileRead(uint32(ins.Args[0].Imm)); ok {
					add("+sme", "+sve")
				}
				if _, ok := decodeARM64RawSMETileWrite(uint32(ins.Args[0].Imm)); ok {
					add("+sme", "+sve")
				}
				if _, ok := decodeARM64RawSMETileMemory(uint32(ins.Args[0].Imm)); ok {
					add("+sme", "+sve")
				}
				if _, ok := decodeARM64RawSVEFloatImmediate(uint32(ins.Args[0].Imm)); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVEDupM(uint32(ins.Args[0].Imm)); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVEFloatMultiplyAccumulate(uint32(ins.Args[0].Imm)); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVEConvert(uint32(ins.Args[0].Imm)); ok {
					add("+sve")
				}
			}
			if arm64CTERMOps[Op(op)] {
				add("+sve")
			}
			if op == "VPMULL" || op == "VPMULL2" {
				add("+aes")
			}
			if op == "AESE" || op == "AESD" || op == "AESMC" || op == "AESIMC" {
				add("+aes")
			}
			if strings.HasPrefix(op, "SHA1") || strings.HasPrefix(op, "SHA256") {
				add("+sha2")
			}
			if strings.HasPrefix(op, "SHA512") {
				add("+sha3")
			}
			if strings.HasPrefix(op, "CRC32") {
				add("+crc")
			}
			if op == "ADDVL" || op == "ADDPL" || op == "RDVL" || op == "ZADR" || op == "ZDUP" || op == "ZADD" || op == "ZSEL" || op == "ZMUL" || op == "ZAND" || op == "ZBIC" || op == "ZEOR" || op == "ZORR" || op == "ZTBL" || op == "ZUMULLB" {
				add("+sve")
			}
			if _, ok := arm64SVEShiftSpecs[Op(op)]; ok {
				add("+sve")
			}
			if spec, ok := arm64SVEImmediateShiftSpecs[Op(op)]; ok {
				add("+sve")
				if spec.sve2 {
					add("+sve2")
				}
			}
			if _, ok := arm64SVEReverseShiftIntrinsics[Op(op)]; ok {
				add("+sve")
			}
			add(arm64SVEMatrixMultiplyFeatures(Op(op), ins)...)
			if op == "ZADDP" {
				add("+sve", "+sve2")
			}
			if _, ok := arm64SVETailOps[Op(op)]; ok {
				add("+sve", "+cpa")
			}
			if _, ok := arm64SVEMultiplyAddTailOps[Op(op)]; ok {
				add("+sve", "+cpa")
			}
			if _, ok := arm64SVEVectorPredicateIncDecSpecs[Op(op)]; ok {
				add("+sve")
			}
			if _, ok := arm64SVEAddSubSpecs[Op(op)]; ok {
				add("+sve")
			}
			if _, ok := arm64SVEFloatAddSubSpecs[Op(op)]; ok {
				add("+sve")
			}
			if op == "ZFMUL" || op == "ZFMULX" {
				add("+sve")
			}
			if _, ok := arm64SVEFloatTrigIntrinsics[Op(op)]; ok {
				add("+sve")
			}
			if op == "ZFTMAD" || op == "ZFCMLA" {
				add("+sve")
			}
			if _, ok := arm64SVEFloatMultiplyAccumulateSpecs[Op(op)]; ok {
				add("+sve")
			}
			if _, ok := arm64SVEMultiplyAccumulateSpecs[Op(op)]; ok {
				add("+sve")
				if arm64SVEMultiplyAccumulateNeedsSVE2(ins) {
					add("+sve2")
				}
			}
			if op == "ZBFDOT" {
				add("+bf16", "+sve")
			}
			if _, ok := arm64SVEIntegerDotSpecs[Op(op)]; ok {
				add("+sve", "+sve2", arm64SVEIntegerDotFeature(ins))
				if op == "ZSUDOT" || op == "ZUSDOT" {
					add("+i8mm")
				}
			}
			if _, ok := arm64SVEAESMixIntrinsics[Op(op)]; ok {
				add("+sve2-aes")
			}
			if _, ok := arm64SVEAESRoundIntrinsics[Op(op)]; ok {
				if arm64SVEAESRoundIsMulti(ins) {
					add("+sve", "+sve-aes2")
				} else {
					add("+sve2-aes")
				}
			}
			if spec, ok := arm64SVEOptionalCryptoSpecs[Op(op)]; ok {
				add(spec.feature)
			}
			if op == "ZREVD" {
				add("+sve", "+sve2p1")
				if arm64SVERevdNeedsSVE2P2(ins) {
					add("+sve2p2")
				}
			}
			if op == "ZPMUL" {
				add("+sve", "+sve2")
			}
			if _, ok := arm64SVEPMULLIntrinsics[Op(op)]; ok {
				add("+sve", "+sve2")
				if arm64SVEPMULLNeedsSVE2AES(ins) {
					add("+sve2-aes")
				}
			}
			if op == "ZPMULL" || op == "ZPMLAL" {
				add("+sve", "+sve-aes2")
			}
			if _, ok := arm64SVESaturatingMultiplyHighIntrinsics[Op(op)]; ok {
				add("+sve")
				add("+sve2")
			}
			if _, ok := arm64SVEComplexMultiplyAccumulateIntrinsics[Op(op)]; ok {
				add("+sve")
				add("+sve2")
			}
			if _, ok := arm64SVEComplexAddIntrinsics[Op(op)]; ok {
				add("+sve", "+sve2")
			}
			if op == "ZXAR" {
				add("+sve", "+sve2")
			}
			if _, ok := arm64SVESaturatingRoundingMultiplyAccumulateHighIntrinsics[Op(op)]; ok {
				add("+sve")
				add("+sve2")
			}
			if spec, ok := arm64SVEFloatMinMaxSpecs[Op(op)]; ok {
				add("+sve")
				if spec.kind == arm64SVEFloatMinMaxPairwise {
					add("+sve2")
				}
				if spec.kind == arm64SVEFloatMinMaxQuadReduce {
					add("+sve2p1")
				}
			}
			if _, ok := arm64SVECharacterMatchIntrinsics[Op(op)]; ok {
				add("+sve", "+sve2")
			}
			if _, ok := arm64SVEHistogramOps[Op(op)]; ok {
				add("+sve", "+sve2")
			}
			if _, ok := arm64SVEFloatReciprocalStepIntrinsics[Op(op)]; ok {
				add("+sve")
			}
			if op == "ZFEXPA" {
				add("+sve")
			}
			if op == "ZFLOGB" {
				add("+sve", "+sve2")
			}
			if op == "ZFCPY" || op == "ZFDUP" {
				add("+sve")
			}
			if op == "ZFDIV" || op == "ZFDIVR" || op == "ZFSCALE" {
				add("+sve")
			}
			if op == "ZSUQADD" || op == "ZUSQADD" {
				add("+sve", "+sve2")
			}
			if op == "ZFCADD" {
				add("+sve", "+sve2")
			}
			if op == "ZDUPW" {
				add("+sve")
			}
			if op == "ZDUPQ" {
				add("+sve", "+sve2p1")
			}
			if op == "ZDUPM" {
				add("+sve")
			}
			if op == "ZFDOT" {
				if sourceBits, destinationBits, ok := arm64SVEFDOTFeatureClass(ins); ok {
					add("+sve", "+sve2")
					if sourceBits == 8 {
						add("+fp8", "+sve2p2")
						if destinationBits == 16 {
							add("+ssve-fp8dot2")
						} else if destinationBits == 32 {
							add("+ssve-fp8dot4")
						}
					} else if sourceBits == 16 && destinationBits == 32 {
						add("+f16f32dot", "+sve2p1")
					}
				}
			}
			if op == "ZCDOT" {
				add("+sve", "+sve2")
			}
			if op == "ZLUTI2" || op == "ZLUTI4" {
				add("+lut", "+sve", "+sve2")
			}
			if _, ok := arm64SVEWideningFloatMLASpecs[Op(op)]; ok {
				if sourceBits, sourceOK := arm64SVEWideningFloatMLAFeatureClass(ins); sourceOK {
					add("+sve", "+sve2")
					if sourceBits == 8 {
						add("+fp8", "+ssve-fp8fma", "+sve2p2")
					}
				}
			}
			if _, ok := arm64SVEMultiNarrowSpecs[Op(op)]; ok {
				add("+sve", "+sve2p1")
			}
			if arm64SVEFloatNarrowConversionOp(Op(op)) {
				add("+sve")
				if Op(op) == "ZFCVTNT" {
					add("+sve2")
					if len(ins.Args) == 3 {
						if _, zeroing := arm64ParseSVEPredicateMode(ins.Args[1], "Z", 7); zeroing {
							add("+sve2p2")
						}
					}
				}
				if arm64SVEFloatNarrowConversionUsesFP8(Op(op), ins) {
					add("+fp8", "+sve2", "+sve2p2")
				}
				if Op(op) == "ZBFCVT" || Op(op) == "ZBFCVTNT" {
					add("+bf16")
				}
			}
			if spec, ok := arm64SVEBFloatArithmeticSpecs[Op(op)]; ok {
				add("+sve")
				if spec.scale {
					add("+sve-bfscale")
				} else {
					add("+sve-b16b16")
				}
			}
			if spec, ok := arm64SVEBFloatMLASpecs[Op(op)]; ok {
				add("+sve")
				switch {
				case spec.subtractLong:
					add("+bf16", "+sve2p1")
				case spec.widening:
					add("+bf16")
				default:
					add("+sve-b16b16")
				}
			}
			if spec, ok := arm64SVEFloatPredicatedPairwiseSpecs[Op(op)]; ok {
				add("+sve")
				if spec.sve2 {
					add("+sve2")
				}
				if spec.faminmax {
					add("+faminmax")
				}
			}
			if spec, ok := arm64SVEFloatUnarySpecs[Op(op)]; ok {
				add("+sve")
				if spec.fptoint {
					add("+fptoint")
				}
			}
			if spec, ok := arm64SVEIntegerUnarySpecs[Op(op)]; ok {
				add("+sve")
				if spec.sve2 {
					add("+sve2")
				}
			}
			if _, ok := arm64SVEPredicateLogicalSpecs[Op(op)]; ok {
				add("+sve")
			}
			if _, ok := arm64SVEPredicateBreakSpecs[Op(op)]; ok {
				add("+sve")
			}
			if _, ok := arm64SVEPredicatePermuteSpecs[Op(op)]; ok {
				add("+sve")
			}
			if _, ok := arm64SVEPredicateStateSpecs[Op(op)]; ok {
				add("+sve")
			}
			if _, ok := arm64SVEPredicateIterateSpecs[Op(op)]; ok {
				add("+sve")
			}
			if _, ok := arm64SVEPredicatePositionIntrinsics[Op(op)]; ok {
				add("+sve", "+sve2p2")
			}
			if _, ok := arm64SVEPredicateCounterOps[Op(op)]; ok {
				add("+sve")
				if arm64SVEPredicateCounterNeedsSVE2P1(Op(op), ins) {
					add("+sve2p1")
				}
			}
			if spec, ok := arm64SVEPredicateWhileSpecs[Op(op)]; ok {
				add("+sve")
				if spec.pointer {
					add("+sve2")
				}
				if arm64SVEPredicateWhileNeedsSVE2P1(ins) {
					add("+sve2p1")
				}
			}
			if _, ok := arm64SVEPredicateIncDecSpecs[Op(op)]; ok {
				add("+sve")
			}
			if _, ok := arm64SVEPredicateMemoryOps[Op(op)]; ok {
				add("+sve")
			}
			if _, ok := arm64SVEWholeVectorMemoryOps[Op(op)]; ok {
				add("+sve")
			}
			if _, ok := arm64SVEVectorPrefetchBits[Op(op)]; ok {
				add("+sve")
			}
			if _, ok := arm64SVENonTemporalMemorySpecs[Op(op)]; ok {
				add("+sve")
				if arm64SVENonTemporalMemoryNeedsSVE2P1(ins) {
					add("+sve2p1")
				}
			}
			if _, ok := arm64SVEOrdinaryMemorySpecs[Op(op)]; ok {
				add("+sve")
				if arm64SVEOrdinaryMemoryNeedsSVE2P1(ins) {
					add("+sve2p1")
				}
			}
			if spec, ok := arm64SVEStructuredMemorySpecs[Op(op)]; ok {
				add("+sve")
				if spec.q {
					add("+sve2p1")
				}
			}
			if _, ok := arm64SVEFirstFaultMemorySpecs[Op(op)]; ok {
				add("+sve")
			}
			if _, ok := arm64SVENonFaultingMemorySpecs[Op(op)]; ok {
				add("+sve")
			}
			if spec, ok := arm64SVEReplicateMemorySpecs[Op(op)]; ok {
				add("+sve")
				if spec.blockBytes == 32 {
					add("+f64mm")
				}
			}
			if op == "ZPMOV" {
				add("+sve", "+sve2p1")
			}
			if op == "ZINDEX" || op == "ZINDEXW" {
				add("+sve")
			}
			if _, ok := arm64SVEInsertBaseSize[Op(op)]; ok {
				add("+sve")
			}
			if _, ok := arm64SVELastSpecs[Op(op)]; ok {
				add("+sve")
			}
			if _, ok := arm64SVECLastSpecs[Op(op)]; ok {
				add("+sve")
			}
			if op == "ZCOMPACT" {
				add("+sve")
				if arm64SVECompactNeedsSVE2P2(ins) {
					add("+sve2p2")
				}
			}
			if op == "ZEXPAND" {
				add("+sve", "+sve2p2")
			}
			if op == "ZMOVPRFX" {
				add("+sve")
			}
			if op == "ZEXT" {
				add("+sve")
			}
			if op == "ZEXTQ" {
				add("+sve", "+sve2p1")
			}
			if op == "ZSPLICE" {
				add("+sve")
			}
			if op == "ZCPY" || op == "ZCPYW" {
				add("+sve")
			}
			if _, ok := arm64SVECopyVectorBaseSize[Op(op)]; ok {
				add("+sve")
			}
			if _, ok := arm64SVEConvertSpecs[Op(op)]; ok {
				add("+sve")
				if op == "ZFCVTLT" || op == "ZFCVTXNT" {
					add("+sve2p2")
				}
			}
			if _, ok := arm64SVECompareSpecs[Op(op)]; ok {
				add("+sve")
			}
			if spec, ok := arm64SVEMinMaxSpecs[Op(op)]; ok {
				add("+sve")
				if spec.kind == arm64SVEMinMaxPairwise {
					add("+sve2")
				}
				if spec.kind == arm64SVEMinMaxQuadReduce {
					add("+sve2p1")
				}
			}
			if spec, ok := arm64SVEIntegerReductionSpecs[Op(op)]; ok {
				add("+sve")
				if spec.quad {
					add("+sve2p1")
				}
			}
			if spec, ok := arm64SVEAddReductionSpecs[Op(op)]; ok {
				add("+sve")
				if spec.kind == arm64SVEFloatAddQuadReduce {
					add("+sve2p1")
				}
			}
			if _, ok := arm64SVEWideningAddSubSpecs[Op(op)]; ok {
				add("+sve", "+sve2")
			}
			if _, ok := arm64SVEShiftLongIntrinsics[Op(op)]; ok {
				add("+sve", "+sve2")
			}
			if spec, ok := arm64SVEAbsoluteDifferenceSpecs[Op(op)]; ok {
				add("+sve")
				if spec.kind != arm64SVEAbsoluteDifference {
					add("+sve2")
				}
			}
			if _, ok := arm64SVEHalvingAddSubIntrinsics[Op(op)]; ok {
				add("+sve", "+sve2")
			}
			if _, ok := arm64SVEDivideIntrinsics[Op(op)]; ok {
				add("+sve")
			}
			if _, ok := arm64SVETernaryBitwiseSpecs[Op(op)]; ok {
				add("+sve", "+sve2")
			}
			if _, ok := arm64SVEEORInterleaveIntrinsics[Op(op)]; ok {
				add("+sve", "+sve2")
			}
			if _, ok := arm64SVEBitPermuteIntrinsics[Op(op)]; ok {
				add("+sve", "+sve-bitperm", "+sve2")
			}
			if _, ok := arm64SVECarryLongIntrinsics[Op(op)]; ok {
				add("+sve", "+sve2")
			}
			if spec, ok := arm64SVEClampSpecs[Op(op)]; ok {
				if spec.kind == arm64SVEClampBFloat {
					add("+sve", "+sve-b16b16")
				} else {
					add("+sve", "+sve2p1")
				}
			}
			if _, ok := arm64SVEUnpackIntrinsics[Op(op)]; ok {
				add("+sve")
			}
			if _, ok := arm64SVESaturatingNarrowSpecs[Op(op)]; ok {
				add("+sve", "+sve2")
			}
			if _, ok := arm64SVEShiftNarrowSpecs[Op(op)]; ok {
				add("+sve", "+sve2")
			}
			if _, ok := arm64SVESaturatingShiftNarrowSpecs[Op(op)]; ok {
				add("+sve", "+sve2")
			}
			if op == "ZDUP" && len(ins.Args) == 2 {
				if _, bits, _, ok := arm64ParseSVEDupElementReg(ins.Args[0]); ok && bits == 128 {
					add("+sve2p1")
				}
			}
			if op == "ZMUL" && arm64SVEMultiplyNeedsSVE2(ins) {
				add("+sve2")
			}
			if _, ok := arm64SVEMultiplyHighIntrinsics[Op(op)]; ok {
				add("+sve")
				if arm64SVEMultiplyHighNeedsSVE2(ins) {
					add("+sve2")
				}
			}
			if _, ok := arm64SVEVariableShiftSpecs[Op(op)]; ok {
				add("+sve", "+sve2")
			}
			if op == "ZTBL" && arm64SVETableNeedsSVE2(ins) {
				add("+sve2")
			}
			if _, ok := arm64SVETableExtensionIntrinsics[Op(op)]; ok {
				add("+sve")
				if op == "ZTBX" {
					add("+sve2")
				} else {
					add("+sve2p1")
				}
			}
			if _, ok := arm64SVEMultiplyLongSpecs[Op(op)]; ok {
				add("+sve", "+sve2")
			}
			if _, ok := arm64SVEMultiplyAccumulateLongIntrinsics[Op(op)]; ok {
				add("+sve", "+sve2")
			}
			if _, ok := arm64SVEPermuteIntrinsics[Op(op)]; ok {
				add("+sve")
				if arm64SVEIsQPermuteOp(Op(op)) {
					add("+sve2p1")
				} else if arm64SVEPermuteNeedsF64MM(ins) {
					add("+f64mm")
				}
			}
			if op == "WORD" && len(ins.Args) == 1 && ins.Args[0].Kind == OpImm && ins.Args[0].ImmRaw == "" {
				word := uint32(ins.Args[0].Imm)
				if decoded, err := decodeARM64RawWordInstruction(ins); err == nil {
					decodedFeatures := inferFuncTargetFeaturesForGOARCH(ArchARM64, goarch, Func{Instrs: []Instr{decoded}})
					add(strings.Split(decodedFeatures, ",")...)
				}
				if _, ok := decodeARM64RawAES(word); ok {
					add("+aes")
				}
				if _, ok := decodeARM64RawSM4(word); ok {
					add("+sm4")
				}
				if _, ok := decodeARM64RawRDMA(word); ok {
					add("+rdm")
				}
				if _, ok := decodeARM64RawFloatMultiplyLong(word); ok {
					add("+fp16fml")
				}
				if _, ok := decodeARM64RawHalfFMA(word); ok {
					add("+fullfp16")
				}
				if _, ok := decodeARM64RawScalarHalfUnary(word); ok {
					add("+fullfp16")
				}
				if form, ok := decodeARM64RawScalarVectorFCVTZ(word); ok && form.bits == 16 {
					add("+fullfp16")
				}
				if form, ok := decodeARM64RawFMULByElement(word); ok && form.arrangement.elementBits == 16 {
					add("+fullfp16")
				}
				if form, ok := decodeARM64RawFloatBinary(word); ok && form.arrangement.elementBits == 16 {
					add("+fullfp16")
				}
				if form, ok := decodeARM64RawReciprocalEstimate(word); ok && form.arrangement.elementBits == 16 {
					add("+fullfp16")
				}
				if form, ok := decodeARM64RawFloatImmediate(word); ok && form.arrangement.elementBits == 16 {
					add("+fullfp16")
				}
				if form, ok := decodeARM64RawScalarFloatBinary(word); ok && form.bits == 16 {
					add("+fullfp16")
				}
				if form, ok := decodeARM64RawScalarFloatCompare(word); ok && form.bits == 16 {
					add("+fullfp16")
				}
				if form, ok := decodeARM64RawConditionalCompare(word); ok && form.bits == 16 {
					add("+fullfp16")
				}
				if form, ok := decodeARM64RawFloatCompare(word); ok && form.arrangement.elementBits == 16 {
					add("+fullfp16")
				}
				if form, ok := decodeARM64RawFloatMinMaxAcross(word); ok && form.arrangement.elementBits == 16 {
					add("+fullfp16")
				}
				if form, ok := decodeARM64RawScalarFloatSelect(word); ok && form.bits == 16 {
					add("+fullfp16")
				}
				if form, ok := decodeARM64RawScalarFloatImmediate(word); ok && form.bits == 16 {
					add("+fullfp16")
				}
				if form, ok := decodeARM64RawScalarIntToFloat(word); ok && form.floatBits == 16 {
					add("+fullfp16")
				}
				if form, ok := decodeARM64RawFloatGPMove(word); ok && form.bits == 16 {
					add("+fullfp16")
				}
				if _, ok := decodeARM64RawBFloatConvert(word); ok {
					add("+bf16")
				}
				if _, ok := decodeARM64RawBFloatDot(word); ok {
					add("+bf16")
				}
				if _, ok := decodeARM64RawBFloatMatrix(word); ok {
					add("+bf16")
				}
				if _, ok := decodeARM64RawSHA3(word); ok {
					add("+sha3")
				}
				if form, ok := decodeARM64RawScalarFCVTToInt(word); ok && form.sourceBits == 16 {
					add("+fullfp16")
				}
				if _, ok := decodeARM64RawSVEAddress(word); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVEIndex(word); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVECnt(word); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVEPTrue(word); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVELDST1D(word); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVELDST1W(word); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVEFloat(word); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVEFloatReciprocalStep(word); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVEFloatMinMaxReduction(word); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVEIntegerAddReduction(word); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVELoadStore(word); ok {
					add("+sve")
				}
				if decoded, ok := decodeARM64RawSVEWhile(word); ok {
					add("+sve")
					if arm64SVEPredicateWhileNeedsSVE2P1(decoded) {
						add("+sve2p1")
					}
				}
				if _, ok := decodeARM64RawSVELD1B(word); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVEContiguousMemory(word); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVEUnpack(word); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVEAddPairwiseLong(word); ok {
					add("+sve", "+sve2")
				}
				if _, ok := decodeARM64RawSVEIntegerMinMax(word); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVEIntegerMinMaxReduction(word); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVEPTest(word); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVEMOVPRFX(word); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVELast(word); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVEDupImmediate(word); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVEDupGeneral(word); ok {
					add("+sve")
				}
				if form, ok := decodeARM64RawSVEDupElement(word); ok {
					add("+sve")
					if form.elementBits == 128 {
						add("+sve2p1")
					}
				}
				if _, ok := decodeARM64RawSVEAdd(word); ok {
					add("+sve")
				}
				if op, form, ok := decodeARM64RawSVEAddSub(word); ok {
					add("+sve")
					if form.mode == arm64SVEAddPredicated && arm64SVEAddSubSpecs[op].intrinsic != "" {
						add("+sve2")
					}
				}
				if _, ok := decodeARM64RawSVEShift(word); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVESelect(word); ok {
					add("+sve")
				}
				if form, ok := decodeARM64RawSVEMultiply(word); ok {
					add("+sve")
					if form.mode == arm64SVEMultiplyUnpredicated || form.mode == arm64SVEMultiplyLane {
						add("+sve2")
					}
				}
				if _, ok := decodeARM64RawSVEEOR(word); ok {
					add("+sve")
				}
				if form, ok := decodeARM64RawSVETable(word); ok {
					add("+sve")
					if form.tableCount == 2 {
						add("+sve2")
					}
				}
				if _, ok := decodeARM64RawSVEUMULLB(word); ok {
					add("+sve", "+sve2")
				}
				if _, ok := decodeARM64RawSVEMultiplyAccumulateLong(word); ok {
					add("+sve", "+sve2")
				}
				if form, ok := decodeARM64RawSVEPermute(word); ok {
					add("+sve")
					if form.quad {
						add("+f64mm")
					}
				}
			}
		case ArchARM:
			if op == "WORD" && len(ins.Args) == 1 && ins.Args[0].Kind == OpImm {
				if _, ok := decodeARMRawVFPMove(uint32(ins.Args[0].Imm)); ok {
					add("+vfp2")
				}
				if form, ok := decodeARMRawNEONPairwiseMinMax(uint32(ins.Args[0].Imm)); ok {
					add("+neon")
					if form.floating && form.elementBits == 16 {
						add("+fullfp16")
					}
				}
				if form, ok := decodeARMRawNEONMinMax(uint32(ins.Args[0].Imm)); ok {
					add("+neon")
					if form.floating && form.elementBits == 16 {
						add("+fullfp16")
					}
				}
				if _, ok := decodeARMRawVFPStatusTransfer(uint32(ins.Args[0].Imm)); ok {
					add("+vfp2")
				}
				if _, ok := decodeARMRawVFPScalarArithmetic(uint32(ins.Args[0].Imm)); ok {
					add("+vfp2")
				}
				if form, ok := decodeARMRawNEONMultiplyLane(uint32(ins.Args[0].Imm)); ok {
					add("+neon")
					if form.floating && form.elementBits == 16 {
						add("+fullfp16")
					}
				}
				if _, ok := decodeARMRawNEONConvertFloat32(uint32(ins.Args[0].Imm)); ok {
					add("+neon")
				}
				if _, ok := decodeARMRawNEONMoveLong(uint32(ins.Args[0].Imm)); ok {
					add("+neon")
				}
				if _, ok := decodeARMRawNEONWideningSubtract(uint32(ins.Args[0].Imm)); ok {
					add("+neon")
				}
				if _, ok := decodeARMRawNEONDup(uint32(ins.Args[0].Imm)); ok {
					add("+neon")
				}
				if decoded, err := decodeARMRawWordInstruction(ins); err == nil {
					decodedFeatures := inferFuncTargetFeaturesForGOARCH(ArchARM, goarch, Func{Instrs: []Instr{decoded}})
					add(strings.Split(decodedFeatures, ",")...)
				}
				if _, ok := decodeARMRawVFPImmediate(uint32(ins.Args[0].Imm)); ok {
					add("+vfp2")
				}
				if _, ok := decodeARMRawVMOVPair(uint32(ins.Args[0].Imm)); ok {
					add("+vfp2")
				}
				if _, ok := decodeARMRawVFPMultiple(uint32(ins.Args[0].Imm)); ok {
					add("+vfp2")
				}
				if _, ok := decodeARMRawNEONStructureOne(uint32(ins.Args[0].Imm)); ok {
					add("+neon")
				}
				if _, ok := decodeARMRawNEONEOR(uint32(ins.Args[0].Imm)); ok {
					add("+neon")
				}
			}
			// Go's ARM runtime keeps VFP save/restore instructions in the
			// GOARM=5 image and guards their execution with goarmsoftfp. LLVM
			// still needs VFP enabled while assembling that otherwise-dead path.
			// Attach the feature only to functions which name VFP state or
			// floating-point registers; this does not raise the target-wide CPU
			// baseline.
			for _, arg := range ins.Args {
				var reg string
				switch arg.Kind {
				case OpReg:
					reg = strings.ToUpper(string(arg.Reg))
				case OpIdent:
					reg = strings.ToUpper(arg.Ident)
				default:
					continue
				}
				if reg == "FPCR" || reg == "FPSR" || reg == "FPSCR" || strings.HasPrefix(reg, "F") || strings.HasPrefix(reg, "S") {
					add("+vfp2")
					break
				}
			}
		}
	}

	if len(featureSet) == 0 {
		return ""
	}
	sort.Strings(featureSet)
	return strings.Join(featureSet, ",")
}

// These existing families need no extra ISA. This query supplies no input,
// storage or source permission; physical forms retain their original route.
func x86BaselineGPFeatureInstruction(op Op, ins *Instr, arch string) bool {
	if arch != "amd64" && arch != "386" || ins.Op != op || !x86ResultNamedPredicateInstruction(*ins) {
		return false
	}
	if _, known := x86LockScalarRMWSpecs[op]; known {
		_, _, err := x86LockScalarRMWProperties(op, *ins, arch)
		return err == nil
	}
	if x86LEAWidth(op, arch) != 0 {
		_, err := x86LEAOperandWidth(*ins, arch)
		return err == nil
	}
	if !isX86DirectControlTransfer(op) || isAMD64CounterZeroBranch(op) {
		return false
	}
	if op == OpRET {
		return len(ins.Args) == 0
	}
	// Only existing named/PC branch roles qualify. Indirect and external
	// targets keep the original path; the CFG still owns target binding.
	branch := *ins
	branch.Args = x86DirectTailBranchArgs(branch)
	_, named := fixedLocalBranchLabel(branch)
	return named || x86DirectTailPCBranch(*ins)
}

func isAMD64RawFP16Op(op string) bool {
	base := op
	if dot := strings.IndexByte(op, '.'); dot >= 0 {
		base = op[:dot]
	}
	if base == "VMOVSH" || base == "VMOVW" {
		return true
	}
	if spec, ok := amd64HalfConversionSpecs[base]; ok {
		return spec.rawOnly
	}
	if spec, ok := amd64FMA3Specs[Op(base)]; ok {
		return spec.rawOnly && spec.laneBits == 16
	}
	if spec, ok := amd64SameWidthConversionSpecs[Op(base)]; ok {
		return spec.rawOnly && spec.laneBits == 16
	}
	spec, ok := amd64BinaryFloatingSpecs[Op(base)]
	return ok && spec.rawOnly && spec.laneBits == 16
}
