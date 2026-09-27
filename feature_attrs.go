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
			case op == "VDPPD" || op == "VDPPS":
				add("+avx", "+sse4.1")
			case op == "DPPD" || op == "DPPS":
				add("+sse4.1")
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
			case strings.HasPrefix(op, "ANDN"):
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
			case op == "PCLMULQDQ" || op == "VPCLMULQDQ":
				add("+pclmul", "+sse4.1")
			case op == "PSHUFB" || op == "VPSHUFB":
				add("+ssse3")
			case op == "AESENC" || op == "AESENCLAST" || op == "AESDEC" || op == "AESDECLAST" || op == "AESIMC" || op == "AESKEYGENASSIST" ||
				op == "VAESENC" || op == "VAESENCLAST" || op == "VAESDEC" || op == "VAESDECLAST" || op == "VAESIMC" || op == "VAESKEYGENASSIST":
				add("+aes")
			}
		case ArchARM64:
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
				if _, ok := decodeARM64RawRNDR(word); ok {
					add("+rand")
				}
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
				if _, ok := decodeARM64RawSVEFloatMinMaxReduction(word); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVEIntegerAddReduction(word); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVELoadStore(word); ok {
					add("+sve")
				}
				if _, ok := decodeARM64RawSVEWhileLO(word); ok {
					add("+sve")
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
