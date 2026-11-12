package goasmrules

import (
	"fmt"
	"strconv"
	"strings"
)

// X86PackedBinaryRow retains the owning official table row. Witnesses are
// expectations, not evidence that Go assembled or plan9asm translated them.
type X86PackedBinaryRow struct {
	ID, Opcode string
	Witnesses  []X86PackedBinaryWitness
}

// Unary and immediate AVX rows leave Second empty, as do legacy unary immediates;
// legacy RMW immediates leave First empty and retain data/destination in Second.
// Syntax fields do not certify reads: typed effects own mask and old bytes.
type X86PackedBinaryWitness struct {
	Instruction, Generation    string
	First, Second, Destination string
	Width                      int
	Memory, Masked, Zeroing    bool
	Broadcast                  bool
	MaskResult                 bool
	Encoding                   []byte
}

// X86GPBMIRows retains the complete scalar BMI/bit-field VEX row grammar.
// Shared transport does not merge FLAGS, implicit DX or dual-output semantics.
func X86GPBMIRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `ANDNL ANDNQ BEXTRL BEXTRQ
		BLSIL BLSIQ BLSMSKL BLSMSKQ BLSRL BLSRQ BZHIL BZHIQ MULXL MULXQ
		PDEPL PDEPQ PEXTL PEXTQ RORXL RORXQ SARXL SARXQ SHLXL SHLXQ SHRXL SHRXQ`)
}

// X86PrecisionHalfScalarConversionRows retains all ordinary precision, F16C
// and scalar FP/GP conversions; numerical and native contracts stay separate.
func X86PrecisionHalfScalarConversionRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `VCVTPD2PS VCVTPD2PSX VCVTPD2PSY VCVTPS2PD
  VCVTPH2PS VCVTPS2PH VCVTSD2SS VCVTSS2SD
  VCVTSD2SI VCVTSD2SIQ VCVTSS2SI VCVTSS2SIQ
  VCVTTSD2SI VCVTTSD2SIQ VCVTTSS2SI VCVTTSS2SIQ
  VCVTSD2USIL VCVTSD2USIQ VCVTSS2USIL VCVTSS2USIQ
  VCVTTSD2USIL VCVTTSD2USIQ VCVTTSS2USIL VCVTTSS2USIQ
  VCVTSI2SDL VCVTSI2SDQ VCVTSI2SSL VCVTSI2SSQ
  VCVTUSI2SDL VCVTUSI2SDQ VCVTUSI2SSL VCVTUSI2SSQ`)
}

// X86MoveRemainderRows retains complete scalar, half, GP/vector, sign-mask
// and non-temporal move tables, including named-source shadow alternatives.
func X86MoveRemainderRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `VLDDQU VMASKMOVDQU VMASKMOVPD VMASKMOVPS
		VMOVD VMOVHLPS VMOVHPD VMOVHPS VMOVLHPS VMOVLPD VMOVLPS
		VMOVMSKPD VMOVMSKPS VMOVNTDQ VMOVNTDQA VMOVNTPD VMOVNTPS
		VMOVQ VMOVSD VMOVSS VPMASKMOVD VPMASKMOVQ VPMOVMSKB`)
}

// X86InsertExtractRows retains all original rows, including alternate physical
// encodings shadowed by earlier named-source rows. Selection needs its observer.
func X86InsertExtractRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `VEXTRACTF128 VEXTRACTI128
		VEXTRACTF32X4 VEXTRACTF64X2 VEXTRACTI32X4 VEXTRACTI64X2
		VEXTRACTF32X8 VEXTRACTF64X4 VEXTRACTI32X8 VEXTRACTI64X4
		VEXTRACTPS VPEXTRB VPEXTRW VPEXTRD VPEXTRQ
		VINSERTF128 VINSERTI128 VINSERTF32X4 VINSERTF64X2 VINSERTI32X4 VINSERTI64X2
		VINSERTF32X8 VINSERTF64X4 VINSERTI32X8 VINSERTI64X4 VINSERTPS VPINSRB VPINSRW VPINSRD VPINSRQ`)
}

// X86PermutationShuffleRows retains complete in-lane, whole-vector and block
// permutations. Existing I2/T2 and B/W indexed rows keep their original owner.
func X86PermutationShuffleRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `VPERMILPD VPERMILPS VPERMPD VPERMQ
		VPERMD VPERMPS VPERM2F128 VPERM2I128
		VSHUFF32X4 VSHUFF64X2 VSHUFI32X4 VSHUFI64X2`)
}

// X86LegacyFloatingBinaryRows retains all six legacy PS/PD/SS/SD binary
// families. Shared media encoding does not merge their numerical contracts.
func X86LegacyFloatingBinaryRows(legacy X86LegacyCatalog, _ []X86AVXRule) ([]X86PackedBinaryRow, error) {
	var names []string
	for _, entry := range legacy.Optab {
		if x86LegacyFloatingBinaryMember(entry.Opcode) {
			names = append(names, entry.Opcode)
		}
	}
	if len(names) != 24 {
		return nil, fmt.Errorf("incomplete legacy floating binary source family: %d", len(names))
	}
	return x86PackedBinaryRows(legacy, nil, strings.Join(names, " "))
}

func x86LegacyFloatingBinaryMember(opcode string) bool {
	if len(opcode) < 5 {
		return false
	}
	switch opcode[:len(opcode)-2] {
	case "ADD", "SUB", "MUL", "DIV", "MIN", "MAX":
		switch opcode[len(opcode)-2:] {
		case "PS", "PD", "SS", "SD":
			return true
		}
	}
	return false
}

// X86FloatingImmediateControlRows retains the five complete PS/PD/SS/SD
// immediate-control families. Numerical/environment contracts stay typed.
func X86FloatingImmediateControlRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `
		VGETMANTPS VGETMANTPD VGETMANTSS VGETMANTSD
		VRNDSCALEPS VRNDSCALEPD VRNDSCALESS VRNDSCALESD
		VREDUCEPS VREDUCEPD VREDUCESS VREDUCESD
		VFIXUPIMMPS VFIXUPIMMPD VFIXUPIMMSS VFIXUPIMMSD
		VRANGEPS VRANGEPD VRANGESS VRANGESD`)
}

// X86CompactExpandRows retains both unary directions and all twelve members.
// Go-encoded memory .Z compression remains a terminal #UD witness.
func X86CompactExpandRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `VCOMPRESSPS VCOMPRESSPD VPCOMPRESSB VPCOMPRESSW VPCOMPRESSD VPCOMPRESSQ
		VEXPANDPS VEXPANDPD VPEXPANDB VPEXPANDW VPEXPANDD VPEXPANDQ`)
}

// X86LeadingImmediateVectorRows retains four distinct numerical families on
// the original shared immediate/two-vector/vector-result encoding grammar.
func X86LeadingImmediateVectorRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `VALIGND VALIGNQ
		VPSHLDW VPSHLDD VPSHLDQ VPSHRDW VPSHRDD VPSHRDQ VPTERNLOGD VPTERNLOGQ VDBPSADBW`)
}

// X86TwoSourceImmediateShuffleRows retains the legacy RMW and AVX three-data
// forms. Their shared transport does not combine align and shuffle semantics.
func X86TwoSourceImmediateShuffleRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `PALIGNR VPALIGNR SHUFPD VSHUFPD SHUFPS VSHUFPS`)
}

// X86GFNIRows retains all named Go multiply and affine/inverse GFNI rows.
// Matrix qword broadcast is independent from byte-granular result masking.
func X86GFNIRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `VGF2P8MULB VGF2P8AFFINEQB VGF2P8AFFINEINVQB`)
}

// X86ImmediateIntegerCompareRows retains all signed/unsigned B/W/D/Q
// immediate comparisons, with K results independent from the input width.
func X86ImmediateIntegerCompareRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `VPCMPB VPCMPUB VPCMPW VPCMPUW VPCMPD VPCMPUD VPCMPQ VPCMPUQ`)
}

// X86IntegerTestMaskRows retains only the eight integer AND/nonzero/zero
// tests. The bit-shuffle opcode on their shared ytab has its own semantics.
func X86IntegerTestMaskRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `VPTESTMB VPTESTMW VPTESTMD VPTESTMQ
		VPTESTNMB VPTESTNMW VPTESTNMD VPTESTNMQ`)
}

// X86PackedNumericConversionRows retains ordinary packed FP/integer numeric
// conversions. The six original MMX rows keep their separate region owner.
func X86PackedNumericConversionRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `
		CVTPS2PL CVTTPS2PL CVTPD2PL CVTTPD2PL CVTPL2PS CVTPL2PD
		VCVTPS2DQ VCVTTPS2DQ VCVTPD2DQX VCVTPD2DQY VCVTTPD2DQX VCVTTPD2DQY VCVTPD2DQ VCVTTPD2DQ
		VCVTPD2QQ VCVTPD2UQQ VCVTTPD2QQ VCVTTPD2UQQ VCVTPS2UDQ VCVTTPS2UDQ VCVTUDQ2PS
		VCVTQQ2PD VCVTUQQ2PD VCVTPS2QQ VCVTPS2UQQ VCVTTPS2QQ VCVTTPS2UQQ VCVTUDQ2PD
		VCVTPD2UDQX VCVTTPD2UDQX VCVTQQ2PSX VCVTUQQ2PSX
		VCVTPD2UDQY VCVTTPD2UDQY VCVTQQ2PSY VCVTUQQ2PSY
		VCVTPD2UDQ VCVTTPD2UDQ VCVTQQ2PS VCVTUQQ2PS VCVTDQ2PS VCVTDQ2PD`)
}

// X86PackedIntegerMinMaxRows retains all amd64 legacy and AVX min/max rows.
func X86PackedIntegerMinMaxRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `
		PMAXSB PMAXSW PMAXSD PMAXUB PMAXUW PMAXUD
		PMINSB PMINSW PMINSD PMINUB PMINUW PMINUD
		VPMAXSB VPMAXSW VPMAXSD VPMAXSQ VPMAXUB VPMAXUW VPMAXUD VPMAXUQ
		VPMINSB VPMINSW VPMINSD VPMINSQ VPMINUB VPMINUW VPMINUD VPMINUQ`)
}

// X86PackedAverageMultiplyRows retains the XMM/VEX/EVEX rounded-average,
// word-product, adjacent multiply-add and widened dword-product families.
// MMX rows keep their separate region/EMMS contract and are not included.
func X86PackedAverageMultiplyRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `
		PAVGB PAVGW VPAVGB VPAVGW
		PMULLW PMULHW PMULHUW PMULHRSW VPMULLW VPMULHW VPMULHUW VPMULHRSW
		PMADDUBSW PMADDWL VPMADDUBSW VPMADDWD
		PMULDQ PMULULQ VPMULDQ VPMULUDQ`)
}

// X86PackedLogicalRows retains packed integer and PS/PD bitwise families,
// including the separate EVEX D/Q names. MMX regions remain a separate owner.
func X86PackedLogicalRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `
		PAND PANDN POR PXOR ANDPS ANDPD ANDNPS ANDNPD ORPS ORPD XORPS XORPD
		VPAND VPANDN VPOR VPXOR VANDPS VANDPD VANDNPS VANDNPD VORPS VORPD VXORPS VXORPD
		VPANDD VPANDQ VPANDND VPANDNQ VPORD VPORQ VPXORD VPXORQ`)
}

// X86PackedUnpackRows retains integer and PS/PD low/high interleave families.
// The six MMX rows retain their separate region and memory-access contracts.
func X86PackedUnpackRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `
		PUNPCKLBW PUNPCKHBW PUNPCKLWL PUNPCKHWL PUNPCKLLQ PUNPCKHLQ PUNPCKLQDQ PUNPCKHQDQ
		UNPCKLPS UNPCKHPS UNPCKLPD UNPCKHPD
		VPUNPCKLBW VPUNPCKHBW VPUNPCKLWD VPUNPCKHWD VPUNPCKLDQ VPUNPCKHDQ VPUNPCKLQDQ VPUNPCKHQDQ
		VUNPCKLPS VUNPCKHPS VUNPCKLPD VUNPCKHPD`)
}

// X86PackedNarrowRows retains signed/unsigned saturating dword-to-word and
// word-to-byte packs. The three MMX rows keep their separate region owner.
func X86PackedNarrowRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `
		PACKSSLW PACKSSWB PACKUSDW PACKUSWB VPACKSSDW VPACKSSWB VPACKUSDW VPACKUSWB`)
}

// X86SingleSourceNarrowingRows retains every truncating and saturating store
// row, including Go-encoded memory.Z forms whose architectural result is #UD.
func X86SingleSourceNarrowingRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `
		VPMOVDB VPMOVDW VPMOVQB VPMOVQD VPMOVQW VPMOVWB
		VPMOVSDB VPMOVSDW VPMOVSQB VPMOVSQD VPMOVSQW VPMOVSWB
		VPMOVUSDB VPMOVUSDW VPMOVUSQB VPMOVUSQD VPMOVUSQW VPMOVUSWB`)
}

// X86PackedPerLaneShiftRows retains the complete W/D/Q logical-left,
// logical-right and arithmetic-right per-lane shift families.
func X86PackedPerLaneShiftRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `
		VPSLLVW VPSLLVD VPSLLVQ VPSRLVW VPSRLVD VPSRLVQ VPSRAVW VPSRAVD VPSRAVQ`)
}

// X86PackedUniformByteShiftRows retains complete XMM and AVX uniform lane
// shifts and per-128-bit byte shifts. MMX regions keep their separate owner.
func X86PackedUniformByteShiftRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `
		PSLLW PSLLL PSLLQ PSRLW PSRLL PSRLQ PSRAW PSRAL PSLLO PSRLO
		VPSLLW VPSLLD VPSLLQ VPSRLW VPSRLD VPSRLQ VPSRAW VPSRAD VPSRAQ VPSLLDQ VPSRLDQ`)
}

// X86PackedSignRows retains all B/W/D conditional-sign rows. Go's legacy
// table is XMM-only; VEX adds X/Y forms, without MMX, EVEX or broadcast.
func X86PackedSignRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `PSIGNB PSIGNW PSIGND VPSIGNB VPSIGNW VPSIGND`)
}

// X86PackedAbsRows retains all unary B/W/D/Q ABS rows, including each
// overlapping VEX/EVEX row and the original mask/broadcast attributes.
func X86PackedAbsRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `PABSB PABSW PABSD VPABSB VPABSW VPABSD VPABSQ`)
}

// X86PackedBitCountConflictRows retains all EVEX unary bit-count/conflict rows.
// Their shared encoding grammar does not combine the independent semantic owners.
func X86PackedBitCountConflictRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `VPOPCNTB VPOPCNTW VPOPCNTD VPOPCNTQ VPLZCNTD VPLZCNTQ
		VPCONFLICTD VPCONFLICTQ`)
}

// X86Reciprocal14Rows retains all packed/scalar EVEX reciprocal14 estimates.
// The byte grammar owns roles and tuples, not numerical or native authority.
func X86Reciprocal14Rows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx,
		"VRCP14PS VRCP14PD VRCP14SS VRCP14SD VRSQRT14PS VRSQRT14PD VRSQRT14SS VRSQRT14SD")
}

// X86PackedRotateRows retains the complete immediate and per-lane D/Q rotate family.
// Variable members remain independently owned by the EVEX binary remainder scope.
func X86PackedRotateRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `VPROLD VPROLQ VPRORD VPRORQ
		VPROLVD VPROLVQ VPRORVD VPRORVQ`)
}

// X86PackedDuplicateRows retains all legacy/VEX/EVEX duplicate-element moves.
func X86PackedDuplicateRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx,
		`MOVDDUP MOVSHDUP MOVSLDUP VMOVDDUP VMOVSHDUP VMOVSLDUP`)
}

// X86PackedImmediateShuffleRows retains every non-MMX legacy/VEX/EVEX source row.
// PSHUFL and PSHUFD are distinct optab entries, not frontend-only aliases.
func X86PackedImmediateShuffleRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx,
		`PSHUFL PSHUFD PSHUFHW PSHUFLW VPSHUFD VPSHUFHW VPSHUFLW`)
}

// X86PackedWideningRows retains the complete sign/zero-extension source family.
// Shrinking native tuples and source carriers remain separate from result width.
func X86PackedWideningRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `
		PMOVSXBW PMOVSXBD PMOVSXBQ PMOVSXWD PMOVSXWQ PMOVSXDQ
		PMOVZXBW PMOVZXBD PMOVZXBQ PMOVZXWD PMOVZXWQ PMOVZXDQ
		VPMOVSXBW VPMOVSXBD VPMOVSXBQ VPMOVSXWD VPMOVSXWQ VPMOVSXDQ
		VPMOVZXBW VPMOVZXBD VPMOVZXBQ VPMOVZXWD VPMOVZXWQ VPMOVZXDQ`)
}

// X86PackedBroadcastRows retains scalar, block, GP and K-data broadcast rows.
func X86PackedBroadcastRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `
		VPBROADCASTB VPBROADCASTW VPBROADCASTD VPBROADCASTQ VBROADCASTSS VBROADCASTSD
		VBROADCASTI32X2 VBROADCASTF32X2 VBROADCASTF32X4 VBROADCASTF64X2 VBROADCASTI32X4 VBROADCASTI64X2
		VBROADCASTF32X8 VBROADCASTF64X4 VBROADCASTI32X8 VBROADCASTI64X4
		VPBROADCASTMB2Q VPBROADCASTMW2D VBROADCASTF128 VBROADCASTI128`)
}

// X86PackedMoveRows retains the twelve AVX whole-vector move names. Legacy
// moves are separate; register alternatives belong to the first store rows.
func X86PackedMoveRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `VMOVDQA VMOVDQU VMOVAPD VMOVAPS VMOVUPD VMOVUPS
		VMOVDQA32 VMOVDQA64 VMOVDQU8 VMOVDQU16 VMOVDQU32 VMOVDQU64`)
}

// X86PackedHorizontalIntegerRows retains the XMM and VEX horizontal add/sub
// rows. PHADDD's distinct MMX row keeps its independent region/EMMS owner.
func X86PackedHorizontalIntegerRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `
		PHADDW PHADDD PHADDSW PHSUBW PHSUBD PHSUBSW
		VPHADDW VPHADDD VPHADDSW VPHSUBW VPHSUBD VPHSUBSW`)
}

// X86PackedByteShuffleRows retains byte-indexed vector permutations. The
// separate VPSHUFBITQMB bit-to-mask family does not share this operand grammar.
func X86PackedByteShuffleRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `PSHUFB VPSHUFB`)
}

// X86PackedIntegerCompareRows retains both vector and mask results. MMX's
// six legacy rows retain their separate region and EMMS contract.
func X86PackedIntegerCompareRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `
		PCMPEQB PCMPEQW PCMPEQL PCMPEQQ PCMPGTB PCMPGTW PCMPGTL PCMPGTQ
		VPCMPEQB VPCMPEQW VPCMPEQD VPCMPEQQ VPCMPGTB VPCMPGTW VPCMPGTD VPCMPGTQ`)
}

// X86PackedMaskBlendRows retains the floating-point and integer mask-blend
// families. Only the PS/PD/D/Q members permit scalar-memory broadcast.
func X86PackedMaskBlendRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `VBLENDMPS VBLENDMPD VPBLENDMB VPBLENDMW VPBLENDMD VPBLENDMQ`)
}

// X86FMA3Rows retains the original named fused floating-point rows. The
// official table owns each member, order, precision and physical encoding.
func X86FMA3Rows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	var names []string
	for _, rule := range avx {
		if strings.HasPrefix(rule.Opcode, "VFM") || strings.HasPrefix(rule.Opcode, "VFNM") {
			names = append(names, rule.Opcode)
		}
	}
	return x86PackedBinaryRows(legacy, avx, strings.Join(names, " "))
}

// X86AVXFloatBinaryRows retains the ordinary PS/PD/SS/SD arithmetic rows;
// legacy, horizontal, alternating and raw FP16 families have separate owners.
func X86AVXFloatBinaryRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `VADDPS VADDPD VADDSS VADDSD VSUBPS VSUBPD VSUBSS VSUBSD
		VMULPS VMULPD VMULSS VMULSD VDIVPS VDIVPD VDIVSS VDIVSD
		VMINPS VMINPD VMINSS VMINSD VMAXPS VMAXPD VMAXSS VMAXSD`)
}

// X86PackedEVEXBinaryRemainderRows retains the remaining _yvblendmpd members.
// Their common encoding grammar does not imply common old-destination reads.
func X86PackedEVEXBinaryRemainderRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `VPDPBUSD VPDPBUSDS VPDPWSSD VPDPWSSDS VPMADD52HUQ VPMADD52LUQ
		VPERMB VPERMW VPERMI2B VPERMI2W VPERMI2D VPERMI2Q VPERMI2PS VPERMI2PD
		VPERMT2B VPERMT2W VPERMT2D VPERMT2Q VPERMT2PS VPERMT2PD VPMULTISHIFTQB
		VPROLVD VPROLVQ VPRORVD VPRORVQ VPSHLDVW VPSHLDVD VPSHLDVQ VPSHRDVW VPSHRDVD VPSHRDVQ`)
}

// X86PackedBinaryPilotRows covers the shared packed add/subtract and D/Q
// low-multiply pilot. MMX and the separate W multiply family are not included.
// PADDD is a frontend alias, not an additional official encoder row.
func X86PackedBinaryPilotRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, `
		PADDB PADDW PADDL PADDQ PADDSB PADDSW PADDUSB PADDUSW
		VPADDB VPADDW VPADDD VPADDQ VPADDSB VPADDSW VPADDUSB VPADDUSW
		PSUBB PSUBW PSUBL PSUBQ PSUBSB PSUBSW PSUBUSB PSUBUSW
		VPSUBB VPSUBW VPSUBD VPSUBQ VPSUBSB VPSUBSW VPSUBUSB VPSUBUSW
		PMULLD VPMULLD VPMULLQ`)
}

func x86PackedBinaryRows(legacy X86LegacyCatalog, avx []X86AVXRule, names string) ([]X86PackedBinaryRow, error) {
	// Scope names are independent of the translator's registry. All operand,
	// width, suffix and encoding axes still come from the original Go rows.
	selected := map[string]bool{}
	for _, name := range strings.Fields(names) {
		selected[name] = false
	}
	var rows []X86PackedBinaryRow
	for _, entry := range legacy.Optab {
		if _, ok := selected[entry.Opcode]; !ok {
			continue
		}
		for _, operand := range entry.Rows {
			classes := strings.Join(operand.Classes, ",")
			if (entry.Ytab == "yxcvm1" && classes == "Yxm,Ymr" || entry.Ytab == "yxcvm2" && classes == "Ymm,Yxr") &&
				operand.RowIndex == 1 && operand.ZCase == "Zm_r_xm" && operand.ZOffset == 2 && operand.UnmatchedOffset == 2 {
				continue // Original MMX conversions require a separate physical region.
			}
			if entry.Ytab == "yps" && entry.Prefix == "Py3" && entry.EscapeAdjustment == 0 &&
				(operand.RowIndex == 0 && classes == "Ymm,Ymr" && operand.ZCase == "Zm_r_xm" && operand.ZOffset == 1 && operand.UnmatchedOffset == 0 ||
					operand.RowIndex == 1 && classes == "Yi8,Ymr" && operand.ZCase == "Zibo_m_xm" && operand.ZOffset == 2 && operand.UnmatchedOffset == 1) {
				continue // The sixteen original MMX rows need their region/EMMS owner.
			}
			if operand.RowIndex == 0 && strings.Join(operand.Classes, ",") == "Ymm,Ymr" && operand.UnmatchedOffset == 0 &&
				(entry.Ytab == "ymm" && operand.ZCase == "Zm_r_xm" && operand.ZOffset == 1 ||
					entry.Ytab == "ymmxmm0f38" && entry.Prefix == "Px" && entry.EscapeAdjustment == 1 &&
						operand.ZCase == "Zlitm_r" && operand.ZOffset == 3) {
				continue // MMX regions have a separate owner and EMMS contract.
			}
			witnesses, err := x86PackedLegacyRowWitnesses(entry, operand)
			if err != nil {
				return nil, fmt.Errorf("%s/%d: %w", entry.Opcode, operand.RowIndex, err)
			}
			rows = append(rows, X86PackedBinaryRow{
				ID:     fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, operand.RowIndex),
				Opcode: entry.Opcode, Witnesses: witnesses,
			})
			selected[entry.Opcode] = true
		}
	}
	for index, rule := range avx {
		if _, ok := selected[rule.Opcode]; !ok {
			continue
		}
		witnesses, err := x86PackedAVXRowWitnesses(rule)
		if err != nil {
			return nil, fmt.Errorf("%s/%d: %w", rule.Opcode, rule.RowIndex, err)
		}
		rows = append(rows, X86PackedBinaryRow{
			ID:     fmt.Sprintf("avx/%d/%s/%s/%d", index, rule.Opcode, rule.Ytab, rule.RowIndex),
			Opcode: rule.Opcode, Witnesses: witnesses,
		})
		selected[rule.Opcode] = true
	}
	for name, found := range selected {
		if !found {
			return nil, fmt.Errorf("official packed opcode %s has no retained row", name)
		}
	}
	return rows, nil
}

func x86PackedAVXRowWitnesses(rule X86AVXRule) ([]X86PackedBinaryWitness, error) {
	if x86GPBMITab(rule.Ytab) {
		return x86GPBMIRowWitnesses(rule)
	}
	if x86VSIBTable(rule.Ytab) {
		return x86VSIBRowWitnesses(rule)
	}
	if x86SpecialVectorStateRoute(rule) {
		return x86SpecialVectorStateRowWitnesses(rule)
	}
	if x86ConversionRemainderTable(rule.Ytab) {
		return x86ConversionRemainderRowWitnesses(rule)
	}
	if x86MoveRemainderTable(rule.Ytab) {
		return x86MoveRemainderRowWitnesses(rule)
	}
	if x86KDataTable(rule.Opcode) != "" {
		return x86KDataRowWitnesses(rule)
	}
	if strings.HasPrefix(rule.Ytab, "_yvextract") || strings.HasPrefix(rule.Ytab, "_yvinsert") ||
		rule.Ytab == "_yvpextrw" || rule.Ytab == "_yvpinsrb" {
		return x86InsertExtractRowWitnesses(rule)
	}
	if rule.Ytab == "_yvpermilpd" || rule.Ytab == "_yvpermq" || rule.Ytab == "_yvpermd" ||
		rule.Ytab == "_yvperm2f128" || rule.Ytab == "_yvshuff32x4" {
		return x86PermutationShuffleRowWitnesses(rule)
	}
	if rule.Ytab == "_yvgetmantpd" || rule.Ytab == "_yvfixupimmpd" || rule.Ytab == "_yvfixupimmsd" {
		return x86FloatingImmediateControlRowWitnesses(rule)
	}
	if strings.HasPrefix(rule.Opcode, "VCOMPRESS") || strings.HasPrefix(rule.Opcode, "VPCOMPRESS") ||
		strings.HasPrefix(rule.Opcode, "VEXPAND") || strings.HasPrefix(rule.Opcode, "VPEXPAND") {
		return x86PackedCompactRowWitnesses(rule)
	}
	if rule.Ytab == "_yvalignd" {
		return x86LeadingImmediateVectorRowWitnesses(rule)
	}
	if rule.Ytab == "_yvgf2p8affineinvqb" {
		if rule.Opcode == "VPALIGNR" || rule.Opcode == "VSHUFPS" || rule.Opcode == "VSHUFPD" {
			return x86LeadingImmediateVectorRowWitnesses(rule)
		}
		return x86GFNIAffineRowWitnesses(rule)
	}
	if rule.Opcode == "VGF2P8MULB" {
		if _, err := x86GFNIFormatForRule(rule); err != nil {
			return nil, err
		}
		// Retain the original no-immediate binary witness transport below.
	}
	if rule.Ytab == "_yvpcmpb" || rule.Ytab == "_yvpshufbitqmb" {
		return x86IntegerMaskResultRowWitnesses(rule)
	}
	if strings.HasPrefix(rule.Ytab, "_yvcvt") && x86PackedWideningRatio(rule) == 0 {
		return x86PackedNumericConversionRowWitnesses(rule)
	}
	if rule.Ytab == "_yvpmovdb" || rule.Ytab == "_yvpmovdw" {
		return x86PackedSingleSourceNarrowRowWitnesses(rule)
	}
	if strings.HasPrefix(rule.Opcode, "VBROADCAST") || strings.HasPrefix(rule.Opcode, "VPBROADCAST") {
		return x86PackedBroadcastRowWitnesses(rule)
	}
	move, store := x86PackedMoveTable(rule.Ytab), x86PackedMoveStoreRow(rule)
	shift, extensionRow := x86PackedUniformShiftTable(rule.Ytab), x86PackedImmediateExtensionRow(rule)
	registerImmediate := x86PackedImmediateRegisterRow(rule)
	widening := x86PackedWideningRatio(rule)
	immediate := extensionRow || registerImmediate
	unary := rule.Ytab == "_yvmovddup" || rule.Ytab == "_yvexpandpd" || move || registerImmediate || widening != 0
	syntax, err := x86PackedSyntaxWitnesses(rule, unary)
	if err != nil {
		return nil, err
	}
	masked := rule.ZCase == "Zevex_rm_v_k_r" || rule.ZCase == "Zevex_rm_k_r" ||
		rule.ZCase == "Zevex_i_rm_k_vo" || rule.ZCase == "Zevex_i_rm_k_r" || store && rule.ZCase == "Zevex_r_k_rm"
	kind, stride, width := "vex", 2, 128
	if strings.HasPrefix(rule.ZCase, "Zevex_") {
		kind, stride = "evex", 3
	}
	if extensionRow {
		stride++
	}
	// The validated data/result class owns vector width. Widening has a
	// smaller independent source carrier; mask results keep their data class.
	dataClass := rule.Classes[0]
	if shift || immediate {
		dataClass = rule.Classes[1]
	}
	if widening != 0 {
		dataClass = rule.Classes[len(rule.Classes)-1]
	}
	bank := strings.ToUpper(dataClass[1:2])
	if bank == "Y" {
		width = 256
	} else if bank == "Z" {
		width = 512
	}
	wantClass := map[string]string{"X": "Yxm", "Y": "Yym", "Z": "Yzm"}[bank]
	if kind == "evex" && bank != "Z" {
		wantClass += "Evex"
	}
	wideningTuple := 0
	if widening != 0 {
		wantClass, wideningTuple = x86PackedWideningSource(width/8, widening, kind == "evex")
	}
	if shift && !immediate {
		wantClass = "Yxm"
		if kind == "evex" {
			wantClass += "Evex"
		}
	}
	if extensionRow && kind == "vex" {
		wantClass = "Y" + strings.ToLower(bank) + "r"
	}
	wantOffset := stride
	if kind == "evex" && !masked && rule.Ytab != "_yvpslldq" ||
		kind == "vex" && immediate && rule.Classes[0] == "Yu8" {
		wantOffset = 0
	}
	memoryClass := rule.Classes[0]
	if immediate {
		memoryClass = rule.Classes[1]
	}
	if store {
		memoryClass = rule.Classes[len(rule.Classes)-1]
	}
	if memoryClass != wantClass || rule.ZOffset != wantOffset {
		return nil, fmt.Errorf("generation/class/row stride mismatch")
	}
	header := rule.OpBytes[rule.EncodingOffset]
	optional := []string{kind + "66", kind + "0F", kind + "0F38", kind + "W0", kind + "W1"}
	if move || rule.Ytab == "_yvaddsd" || rule.Ytab == "_yvmovddup" || registerImmediate {
		optional = append(optional, kind+"F2", kind+"F3")
	}
	atoms, err := x86PackedEncodingAtoms(header, []string{
		"avxEscape", kind + strconv.Itoa(width),
	}, optional)
	if err != nil || atoms[kind+"0F"] == atoms[kind+"0F38"] || atoms[kind+"W0"] == atoms[kind+"W1"] {
		return nil, fmt.Errorf("unmodeled packed encoding header %q", header)
	}
	if widening != 0 && (!atoms[kind+"66"] || !atoms[kind+"0F38"] || !atoms[kind+"W0"]) {
		return nil, fmt.Errorf("widening prefix, map or W mode differs from its official transport")
	}
	duplicate := rule.Ytab == "_yvmovddup" && (atoms[kind+"F2"] || atoms[kind+"F3"])
	if duplicate && (!atoms[kind+"0F"] || kind == "vex" && !atoms[kind+"W0"] ||
		kind == "evex" && atoms[kind+"F2"] != atoms[kind+"W1"]) {
		return nil, fmt.Errorf("duplicate prefix, map or W mode differs from its official transport")
	}
	if registerImmediate && (!atoms[kind+"0F"] || !atoms[kind+"W0"]) {
		return nil, fmt.Errorf("shuffle map or W mode differs from its official transport")
	}
	if (shift || extensionRow) && (!atoms[kind+"66"] || !atoms[kind+"0F"] ||
		(kind == "vex" || rule.Ytab == "_yvpslldq") && !atoms[kind+"W0"]) {
		return nil, fmt.Errorf("shift prefix or W mode differs from its official transport")
	}
	mapByte, wBit, length, pp := byte(1), byte(0), byte(0), byte(0)
	for index, prefix := range []string{"66", "F3", "F2"} {
		if atoms[kind+prefix] {
			if pp != 0 {
				return nil, fmt.Errorf("conflicting packed mandatory prefixes")
			}
			pp = byte(index + 1)
		}
	}
	if registerImmediate && pp == 0 {
		return nil, fmt.Errorf("shuffle requires its retained mandatory prefix")
	}
	if atoms[kind+"0F38"] {
		mapByte = 2
	}
	if atoms[kind+"W1"] {
		wBit = 0x80
	}
	if width == 256 {
		length = 1
	} else if width == 512 {
		length = 2
	}
	if kind == "evex" {
		features := rule.OpBytes[rule.EncodingOffset+1]
		tuple := width / 8
		optional := []string{"evexZeroingEnabled", "evexBcstN4", "evexBcstN8"}
		if widening != 0 {
			tuple, optional = wideningTuple, []string{"evexZeroingEnabled"}
		}
		if registerImmediate {
			optional = []string{"evexZeroingEnabled"}
			if atoms["evex66"] {
				optional = append(optional, "evexBcstN4")
			}
		}
		if duplicate {
			optional = []string{"evexZeroingEnabled"}
			if width == 128 && atoms["evexF2"] {
				tuple = 8 // DDUP.X reads m64; other duplicate tuples stay full width.
			}
		}
		if shift && !immediate {
			tuple = 16 // Uniform count access stays m128 for X/Y/Z data.
		}
		if move || shift && (!immediate || rule.Ytab == "_yvpslldq") {
			optional = []string{"evexZeroingEnabled"}
		}
		if rule.Ytab == "_yvaddsd" || rule.Ytab == "_yvgetexpsd" {
			tuple = 4
			if wBit != 0 {
				tuple = 8
			}
			optional = []string{"evexZeroingEnabled"}
		}
		if rule.Ytab == "_yvaddpd" && width == 512 || rule.Ytab == "_yvaddsd" {
			optional = append(optional, "evexRoundingEnabled", "evexSaeEnabled")
		}
		if rule.Ytab == "_yvpslldq" {
			optional = nil // Per-128-bit byte shifts have neither mask nor BCST.
		}
		flags, err := x86PackedEncodingAtoms(features, []string{"evexN" + strconv.Itoa(tuple)}, optional)
		if err != nil || flags["evexBcstN4"] && flags["evexBcstN8"] {
			return nil, fmt.Errorf("unmodeled packed encoding features %q", features)
		}
	}
	opcodeIndex := rule.EncodingOffset + stride - 1
	if extensionRow {
		opcodeIndex--
	}
	opcode, err := strconv.ParseUint(rule.OpBytes[opcodeIndex], 0, 8)
	if err != nil {
		return nil, fmt.Errorf("packed opcode is not a byte literal")
	}
	var extension uint64
	if extensionRow {
		extension, err = strconv.ParseUint(rule.OpBytes[opcodeIndex+1], 0, 8)
		if err != nil || extension > 7 {
			return nil, fmt.Errorf("immediate opcode extension is not a three-bit literal")
		}
	}
	var witnesses []X86PackedBinaryWitness
	for _, instruction := range syntax {
		if kind == "evex" {
			// High banks force EVEX even for unmasked X/Y forms. Low-bank
			// syntax alone cannot identify overlapping VEX/EVEX rows.
			if widening != 0 {
				sourceBank := strings.ToUpper(rule.Classes[0][1:2])
				if sourceBank != bank {
					instruction = strings.Replace(instruction, sourceBank+"0", sourceBank+"16", 1)
				}
			}
			instruction = strings.NewReplacer(bank+"0", bank+"16", bank+"1", bank+"17", bank+"2", bank+"18").Replace(instruction)
		}
		if kind == "evex" && shift && !immediate {
			instruction = strings.ReplaceAll(instruction, "X0", "X16")
		}
		fields := strings.Fields(instruction)
		operands := strings.Split(fields[1], ",")
		second, vvvv, vprime := operands[1], byte(0x70), byte(0)
		first := operands[0]
		if immediate {
			first, second = operands[1], ""
		}
		if extensionRow {
			vvvv = 0x68 // Destination 2/18 is vvvv/V' only in /digit formats.
		}
		if unary {
			// Unary encodings reserve VEX.vvvv and EVEX.V' as ones;
			// the mask and merging destination remain separate inputs.
			second, vvvv, vprime = "", 0x78, 0x08
		}
		witness := X86PackedBinaryWitness{
			Instruction: instruction, Generation: kind, Width: width,
			First: first, Second: second, Destination: operands[len(operands)-1],
			Memory: first == "(AX)", Masked: masked,
			Zeroing: strings.HasSuffix(fields[0], ".Z"), Broadcast: strings.Contains(fields[0], ".BCST"),
			MaskResult: rule.Classes[len(rule.Classes)-1] == "Yk",
		}
		modrm := byte(0xd0) // destination 2/18, r/m register 0/16.
		memory := witness.Memory || store && witness.Destination == "(AX)"
		if store {
			modrm = 0xc2 // source 0/16 owns ModRM.reg; destination 2/18 is r/m.
		}
		if memory {
			modrm = 0x10 // the only memory witness is the undisturbed (AX).
			if store {
				modrm = 0x00
			}
		}
		if extensionRow {
			modrm = 0xc0 | byte(extension)<<3
			if memory {
				modrm = byte(extension) << 3
			}
		}
		p0, p2 := byte(0), byte(0)
		if kind == "evex" {
			p0, p2 = byte(0xa0), length<<5|vprime
			if memory {
				p0 = 0xe0
			}
			if extensionRow {
				p0 |= 0x10 // ModRM.reg is /digit, not destination register 18.
			}
			if witness.MaskResult {
				p0 |= 0x10 // K2 has no destination bit 4, unlike vector 18.
			}
			if masked {
				p2 |= 1 // K1; binary V' is zero for the second source 17.
			}
			if witness.Zeroing {
				p2 |= 0x80
			}
			if witness.Broadcast {
				p2 |= 0x10
			}
			if strings.Contains(fields[0], ".SAE") {
				p2 |= 0x10 // SAE keeps LL; embedded rounding replaces it below.
			}
			for control, suffix := range []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"} {
				if strings.Contains(fields[0], "."+suffix) {
					p2 = p2&^0x60 | byte(control)<<5 | 0x10
				}
			}
		}
		transport := x86PackedAVXOpcode{kind, mapByte, wBit, pp, length, byte(opcode)}
		witness.Encoding = transport.bytes(vvvv, p0, p2, modrm)
		if immediate {
			value, err := strconv.ParseInt(strings.TrimPrefix(operands[0], "$"), 0, 16)
			if err != nil || value < -128 || value > 255 {
				return nil, fmt.Errorf("shift witness has no byte immediate")
			}
			witness.Encoding = append(witness.Encoding, byte(value))
		}
		witnesses = append(witnesses, witness)
	}
	return witnesses, nil
}

// X86SpecialVectorStateRows retains the nine complete non-GP/non-VSIB closures.
func X86SpecialVectorStateRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	return x86PackedBinaryRows(legacy, avx, x86SpecialVectorStateNames)
}

func x86PackedEncodingAtoms(expression string, required, optional []string) (map[string]bool, error) {
	allowed, found := map[string]bool{}, map[string]bool{}
	for _, term := range append(append([]string(nil), required...), optional...) {
		allowed[term] = true
	}
	for _, term := range strings.FieldsFunc(expression, func(r rune) bool {
		return r == '|' || r == '(' || r == ')' || r == ' ' || r == '\t' || r == '\n'
	}) {
		if !allowed[term] || found[term] {
			return nil, fmt.Errorf("unrecognized or repeated encoding term %s", term)
		}
		found[term] = true
	}
	for _, term := range required {
		if !found[term] {
			return nil, fmt.Errorf("missing encoding term %s", term)
		}
	}
	return found, nil
}

func x86PackedLegacyRowWitnesses(entry X86LegacyOpcode, row X86LegacyOperand) ([]X86PackedBinaryWitness, error) {
	// Captured source must retain the whole original schema/payload even
	// when this old consumer selects only its ordinary XMM row. Only old
	// fixtures with neither rows nor a source expression use the partial path.
	var capturedEncoding []byte
	if (entry.Ytab == "yxcvm1" || entry.Ytab == "yxcvm2" || entry.Ytab == "ymmxmm0f38") &&
		(len(entry.Rows) != 0 || entry.OpcodeExpression != "") {
		var err error
		capturedEncoding, err = x86LegacyMediaX87Encoding(entry, row)
		if err != nil {
			return nil, err
		}
	}
	scalarConversion := x86LegacyScalarConversionTable(entry.Ytab)
	var scalar x86LegacyScalarConversionForm
	if scalarConversion {
		var err error
		scalar, err = x86LegacyScalarConversionProperties(entry, row)
		if err != nil {
			return nil, err
		}
	}
	if entry.Ytab == "yxshuf" || entry.Ytab == "yaes" {
		encoding, err := x86LegacyLiteralSIMDEncoding(entry, row)
		if err != nil {
			return nil, err
		}
		if len(entry.OpBytes) > 2 {
			return x86LegacyLiteralSIMDWitnesses(entry, encoding), nil
		}
		// Keep the original six placeholder-row syntax fields unchanged.
	}
	literal := entry.Ytab == "ymmxmm0f38" && entry.Prefix == "Px" && entry.EscapeAdjustment == 1 &&
		row.RowIndex == 1 && row.ZCase == "Zlitm_r" && row.ZOffset == 5 && row.UnmatchedOffset == 4
	shift := entry.Ytab == "yps" || entry.Ytab == "ypsdq"
	immediate := shift && strings.Join(row.Classes, ",") == "Yi8,Yxr"
	shuffle := (entry.Ytab == "yxshuf" || entry.Ytab == "ypalignr") && strings.Join(row.Classes, ",") == "Yu8,Yxm,Yxr"
	conversion := entry.Ytab == "yxcvm1" || entry.Ytab == "yxcvm2"
	if entry.Kind != "encoding" || entry.EscapeAdjustment != 0 && !literal ||
		strings.Join(row.Classes, ",") != "Yxm,Yxr" && !immediate && !shuffle && !scalarConversion {
		return nil, fmt.Errorf("unmodeled legacy packed operand row")
	}
	// Reuse the complete encoding for the original ordinary conversion and
	// XMM literal rows. New MMX and other source roles retain the old refusal.
	if capturedEncoding != nil && (conversion && row.RowIndex == 0 || literal) {
		return x86LegacyMediaCarrierWitnesses(entry.Opcode, []string{"Yxm", "Yxr"}, capturedEncoding, true), nil
	}
	prefix, offset, opcodeBytes := []byte{0x66, 0x0f}, 0, 1
	terminator := 0
	switch {
	case scalarConversion:
		prefix, offset = []byte{scalar.mandatory, 0x0f}, scalar.opcodeOffset
		if scalar.wide {
			prefix = []byte{scalar.mandatory, 0x48, 0x0f}
		}
	case conversion && row.RowIndex == 0 && row.ZCase == "Zm_r_xm" && row.ZOffset == 2 && row.UnmatchedOffset == 0 && len(entry.OpBytes) == 4:
		if entry.Prefix == "Px" && (entry.OpBytes[2] == "Pe" || entry.OpBytes[2] == "Pm") {
			mandatory := map[string]byte{"Pe": 0x66, "Pf2": 0xf2, "Pf3": 0xf3}[entry.OpBytes[0]]
			if mandatory == 0 {
				return nil, fmt.Errorf("unmodeled packed conversion mandatory prefix")
			}
			prefix, offset = []byte{mandatory, 0x0f}, 1
		} else if entry.Ytab == "yxcvm2" && entry.Prefix == "Pm" && entry.OpBytes[1] == "0" && entry.OpBytes[3] == "0" {
			prefix = []byte{0x0f}
		} else {
			return nil, fmt.Errorf("unmodeled packed conversion complete prefix payload")
		}
	case entry.Ytab == "yps" && entry.Prefix == "Py3" && entry.EscapeAdjustment == 0:
		if len(entry.OpBytes) != 8 || entry.OpBytes[3] != "Pe" || entry.OpBytes[5] != "Pe" ||
			entry.OpBytes[0] != entry.OpBytes[4] || entry.OpBytes[1] != entry.OpBytes[6] || entry.OpBytes[2] != entry.OpBytes[7] {
			return nil, fmt.Errorf("unmodeled complete Py3 shift payload")
		}
		if !immediate && row.RowIndex == 2 && row.ZCase == "Zm_r_xm" && row.ZOffset == 2 && row.UnmatchedOffset == 3 {
			offset = 4
		} else if immediate && row.RowIndex == 3 && row.ZCase == "Zibo_m_xm" && row.ZOffset == 3 && row.UnmatchedOffset == 5 {
			offset = 6
		} else {
			return nil, fmt.Errorf("unmodeled Py3 XMM shift row")
		}
	case entry.Ytab == "ypsdq" && entry.Prefix == "Pq" && immediate && row.RowIndex == 0 &&
		row.ZCase == "Zibo_m" && row.ZOffset == 2 && row.UnmatchedOffset == 0 && len(entry.OpBytes) == 2:
	case shuffle && row.RowIndex == 0 && row.ZCase == "Zibm_r" && row.ZOffset == 2 && row.UnmatchedOffset == 0 &&
		len(entry.OpBytes) == 2:
		switch {
		case entry.Ytab == "ypalignr" && entry.Prefix == "Pq" && entry.OpBytes[0] == "0x3a" && entry.OpBytes[1] == "0x0f":
			opcodeBytes = 2
		case entry.Ytab == "yxshuf" && (entry.OpBytes[1] == "0" || entry.OpBytes[1] == "00"):
			// The second atom is the original stride placeholder, not /digit.
			if entry.OpBytes[0] == "0xc6" {
				if entry.Opcode == "SHUFPS" && entry.Prefix == "Pm" {
					prefix = []byte{0x0f}
				} else if entry.Opcode != "SHUFPD" || entry.Prefix != "Pq" {
					return nil, fmt.Errorf("unmodeled legacy PS/PD shuffle prefix")
				}
			} else if entry.OpBytes[0] == "0x70" && (entry.Prefix == "Pf2" || entry.Prefix == "Pf3") {
				prefix[0] = map[string]byte{"Pf2": 0xf2, "Pf3": 0xf3}[entry.Prefix]
			} else if entry.Prefix != "Pq" || entry.OpBytes[0] != "0x70" {
				return nil, fmt.Errorf("unmodeled legacy immediate shuffle prefix")
			}
		default:
			return nil, fmt.Errorf("unmodeled legacy immediate shuffle payload")
		}
	case literal:
		// Zlitm_r emits the selected zero-terminated sequence verbatim,
		// including its mandatory prefix and opcode-map bytes.
		prefix, offset, opcodeBytes, terminator = nil, row.UnmatchedOffset, row.ZOffset-1, 1
		if len(entry.OpBytes) != offset+opcodeBytes+terminator ||
			entry.OpBytes[offset-1] != "0" || entry.OpBytes[len(entry.OpBytes)-1] != "0" {
			return nil, fmt.Errorf("unmodeled legacy packed literal boundaries")
		}
	case entry.Ytab == "ymm" && entry.Prefix == "Py1" && row.RowIndex == 1 && row.ZCase == "Zm_r_xm" && row.ZOffset == 2 && row.UnmatchedOffset == 1:
		if len(entry.OpBytes) != 3 || entry.OpBytes[1] != "Pe" || entry.OpBytes[0] != entry.OpBytes[2] {
			return nil, fmt.Errorf("unmodeled Py1 XMM opcode payload")
		}
		offset = 2 // Py1 consumes the Pe at offset 1 before the opcode.
	case x86LegacyFloatingBinaryMember(entry.Opcode):
		if entry.Ytab != "yxm" || len(entry.Rows) != 1 || row.RowIndex != 0 || row.ZCase != "Zm_r_xm" ||
			row.ZOffset != 1 || row.UnmatchedOffset != 0 || len(entry.OpBytes) != 1 {
			return nil, fmt.Errorf("unmodeled complete legacy floating media row")
		}
		// Zm_r_xm calls mediaop after the source prefix switch. In particular
		// Ym emits no prefix there, so mediaop supplies the missing 0F escape.
		// Keep the source literal; neither this path nor the scalar suffix
		// alone grants another family's mandatory-prefix capability.
		switch suffix := entry.Opcode[len(entry.Opcode)-2:]; {
		case suffix == "PS" && (entry.Prefix == "Pm" || entry.Prefix == "Ym"):
			prefix = []byte{0x0f}
		case suffix == "PD" && (entry.Prefix == "Pe" || entry.Prefix == "Pq"):
		case suffix == "SS" && entry.Prefix == "Pf3":
			prefix = []byte{0xf3, 0x0f}
		case suffix == "SD" && entry.Prefix == "Pf2":
			prefix = []byte{0xf2, 0x0f}
		default:
			return nil, fmt.Errorf("legacy floating media prefix conflicts with its source class")
		}
	case entry.Ytab == "yxm" && (entry.Prefix == "Pe" || entry.Prefix == "Pq" || entry.Prefix == "Pm") &&
		row.RowIndex == 0 && row.ZCase == "Zm_r_xm" && row.ZOffset == 1 && row.UnmatchedOffset == 0:
		if entry.Prefix == "Pm" {
			prefix = []byte{0x0f}
		}
	case entry.Ytab == "yxm" && row.RowIndex == 0 && row.ZCase == "Zm_r_xm" &&
		row.ZOffset == 1 && row.UnmatchedOffset == 0 && len(entry.OpBytes) == 1 &&
		(entry.Prefix == "Pf2" && entry.OpBytes[0] == "0x12" ||
			entry.Prefix == "Pf3" && (entry.OpBytes[0] == "0x12" || entry.OpBytes[0] == "0x16")):
		// Only the duplicate move payloads join this prefix class; scalar
		// arithmetic and conversion yxm rows keep their separate contracts.
		prefix = []byte{0xf2, 0x0f}
		if entry.Prefix == "Pf3" {
			prefix[0] = 0xf3
		}
	case entry.Ytab == "yxm_q4" && entry.Prefix == "Pq4" && row.RowIndex == 0 && row.ZCase == "Zm_r" && row.ZOffset == 1 && row.UnmatchedOffset == 0:
		prefix = append(prefix, 0x38)
	case entry.Ytab == "ymshufb" && entry.Prefix == "Pq" && row.RowIndex == 0 && row.ZCase == "Zm2_r" && row.ZOffset == 2 && row.UnmatchedOffset == 0:
		// Go's Zm2_r emits two selected opcode bytes before ModRM. They
		// are payload, not another mandatory prefix or a mnemonic lookup.
		opcodeBytes = 2
	default:
		return nil, fmt.Errorf("unmodeled legacy packed prefix/offset rule")
	}
	if !shift && !shuffle && !conversion && len(entry.OpBytes) != offset+opcodeBytes+terminator {
		return nil, fmt.Errorf("unmodeled legacy packed opcode payload")
	}
	encoding := prefix
	for _, value := range entry.OpBytes[offset : offset+opcodeBytes] {
		opcode, err := strconv.ParseUint(value, 0, 8)
		if err != nil || literal && opcode == 0 || scalarConversion && (opcode == 0 || opcode == 0x0f) {
			return nil, fmt.Errorf("legacy packed opcode is not a byte literal")
		}
		encoding = append(encoding, byte(opcode))
	}
	if !scalarConversion && !immediate && !shuffle {
		return x86LegacyMediaCarrierWitnesses(entry.Opcode, []string{"Yxm", "Yxr"}, encoding, true), nil
	}
	sources, extension := []string{"X0", "(AX)"}, uint64(0)
	if scalarConversion {
		sources = []string{"X0", "0(SI)"}
	}
	if immediate {
		var err error
		extension, err = strconv.ParseUint(entry.OpBytes[offset+1], 0, 8)
		if err != nil || extension > 7 {
			return nil, fmt.Errorf("legacy shift opcode extension is not a three-bit literal")
		}
		sources = []string{""}
	}
	var witnesses []X86PackedBinaryWitness
	for _, first := range sources {
		modrm := byte(0xc8)
		memory := first == "(AX)" || scalarConversion && first == "0(SI)"
		if memory {
			modrm = 0x08
			if scalarConversion {
				modrm |= 6
			}
		}
		destination, second := "X1", "X1"
		if scalarConversion {
			if scalar.fromFloat {
				destination, second = "BX", ""
				modrm = modrm&0xc7 | 3<<3
			} else if first == "X0" {
				first, modrm = "CX", modrm&0xf8|1
			}
		}
		instruction := entry.Opcode + " " + first + "," + destination
		encoded := append(append([]byte(nil), encoding...), modrm)
		if shuffle {
			instruction = entry.Opcode + " $7," + first + ",X1"
			if entry.OpBytes[0] == "0x70" {
				second = "" // Unary integer shuffle; align/PS/PD retain old destination.
			}
			encoded = append(encoded, 7)
		}
		if immediate {
			instruction = entry.Opcode + " $-1,X1"
			encoded = append(append([]byte(nil), encoding...), 0xc1|byte(extension)<<3, 255)
		}
		witnesses = append(witnesses, X86PackedBinaryWitness{
			Instruction: instruction, Generation: "legacy", Width: 128,
			First: first, Second: second, Destination: destination, Memory: memory,
			Encoding: encoded,
		})
	}
	return witnesses, nil
}

// X86LegacyLiteralSIMDRows retains two complete source tables. The overlap
// with older shuffle views remains the same original row identity. A carrier
// width is not a memory tuple, numerical input or native-entry permission.
func X86LegacyLiteralSIMDRows(catalog X86LegacyCatalog, arch string) ([]X86PackedBinaryRow, error) {
	if arch != "amd64" && arch != "386" {
		return nil, fmt.Errorf("literal SIMD source view requires an explicit Go x86 mode")
	}
	var rows []X86PackedBinaryRow
	for _, entry := range catalog.Optab {
		if entry.Ytab != "yxshuf" && entry.Ytab != "yaes" {
			continue
		}
		for _, operand := range entry.Rows {
			witnesses, err := x86PackedLegacyRowWitnesses(entry, operand)
			if err != nil {
				return nil, fmt.Errorf("%s/%d: %w", entry.Opcode, operand.RowIndex, err)
			}
			rows = append(rows, X86PackedBinaryRow{
				ID:     fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, operand.RowIndex),
				Opcode: entry.Opcode, Witnesses: witnesses,
			})
		}
	}
	if len(rows) != 33 {
		return nil, fmt.Errorf("incomplete original literal SIMD source view: rows=%d", len(rows))
	}
	return rows, nil
}

// These single-row Z cases use the selected complete zero-terminated span;
// zoffset is an unmatched-row stride, not the number of literal bytes emitted.
func x86LegacyLiteralSIMDEncoding(entry X86LegacyOpcode, selected X86LegacyOperand) ([]byte, error) {
	fail := func() ([]byte, error) { return nil, fmt.Errorf("unmodeled complete literal SIMD source schema") }
	classes, zcase := []string{"Yxm", "Yxr"}, "Zlitm_r"
	if entry.Ytab == "yxshuf" {
		classes, zcase = []string{"Yu8", "Yxm", "Yxr"}, "Zibm_r"
	} else if entry.Ytab != "yaes" {
		return fail()
	}
	valid := func(row X86LegacyOperand) bool {
		if row.RowIndex != 0 || row.ZCase != zcase || row.ZOffset != 2 || row.UnmatchedOffset != 0 || len(row.Classes) != len(classes) {
			return false
		}
		for index, class := range classes {
			if row.Classes[index] != class {
				return false
			}
		}
		return true
	}
	if entry.Kind != "encoding" || len(entry.Rows) != 1 || !valid(entry.Rows[0]) || !valid(selected) || len(entry.OpBytes) < 2 || len(entry.OpBytes) > 4 {
		return fail()
	}
	literal := make([]byte, len(entry.OpBytes))
	for index, atom := range entry.OpBytes {
		value, err := strconv.ParseUint(atom, 0, 8)
		if err != nil || (value == 0) != (index == len(literal)-1) {
			return fail()
		}
		literal[index] = byte(value)
	}
	literal = literal[:len(literal)-1]
	var prefix []byte
	escape := 0
	switch {
	case entry.Ytab == "yxshuf" && len(literal) == 1 && literal[0] != 0x0f:
		switch entry.Prefix {
		case "Pq":
			prefix = []byte{0x66, 0x0f}
		case "Pf2":
			prefix = []byte{0xf2, 0x0f}
		case "Pf3":
			prefix = []byte{0xf3, 0x0f}
		case "Pm":
			prefix = []byte{0x0f}
		default:
			return fail()
		}
	case entry.Prefix == "Pq" && len(literal) == 2:
		mapByte := byte(0x38)
		if entry.Ytab == "yxshuf" {
			mapByte = 0x3a
		}
		if literal[0] != mapByte {
			return fail()
		}
		prefix = []byte{0x66, 0x0f}
	case entry.Ytab == "yaes" && entry.Prefix == "Px" && len(literal) == 3 && literal[0] == 0x0f && literal[1] == 0x38:
		// Go emits the selected leading 0F before PutOpBytesLit advances;
		// the combined source span retains it exactly once.
		escape = 1
	default:
		return fail()
	}
	if entry.EscapeAdjustment != escape {
		return fail()
	}
	return append(prefix, literal...), nil
}

func x86LegacyLiteralSIMDWitnesses(entry X86LegacyOpcode, encoding []byte) []X86PackedBinaryWitness {
	var witnesses []X86PackedBinaryWitness
	for _, source := range []string{"X0", "(AX)"} {
		modrm := byte(0xc8)
		if source == "(AX)" {
			modrm = 0x08
		}
		instruction := entry.Opcode + " " + source + ",X1"
		code := append(append([]byte(nil), encoding...), modrm)
		if entry.Ytab == "yxshuf" {
			instruction = entry.Opcode + " $7," + source + ",X1"
			code = append(code, 7)
		}
		witnesses = append(witnesses, X86PackedBinaryWitness{Instruction: instruction, Generation: "legacy", Width: 128,
			First: source, Second: "X1", Destination: "X1", Memory: source == "(AX)", Encoding: code})
	}
	return witnesses
}
