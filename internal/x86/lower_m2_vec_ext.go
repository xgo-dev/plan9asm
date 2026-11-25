package x86

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// M2 Families 3-6:
//   - Family 3: Packed Int Extended (VPMOV narrow/mask, PHADD/PHSUB, PMADD/VNNI/52,
//     VPSHLD/VPSHRD funnel shifts, MPSADBW/VDBPSADBW/VPMULTISHIFTQB, PSHUFW)
//   - Family 4: Vec Compare & Test (VCMPPS/PD/SS/SD, VPTESTM*/VPTESTNM*, PTEST, VTESTPS/PD)
//   - Family 5: Gather & Scatter (VGATHER*/VPGATHER*/VSCATTER*/VPSCATTER*)
//   - Family 6: Permute/Expand/Conflict/LZCNT/Rotate/Subvec-Broadcast/K-Test/VPSHUFBITQMB

var x86M2VecExtSpecs = []asm.OpSpec{
	// Family 3: Packed Int Extended
	{Op: "PSHUFW", Family: asm.FamilyVecShuffle, LaneBits: 16, Effect: asm.EffectWriteOnly, LLVMOp: "pshufw_mmx"},
	{Op: "VPMOVB2M", Family: asm.FamilyMask, LaneBits: 8, Effect: asm.EffectWriteOnly, LLVMOp: "v2m"},
	{Op: "VPMOVW2M", Family: asm.FamilyMask, LaneBits: 16, Effect: asm.EffectWriteOnly, LLVMOp: "v2m"},
	{Op: "VPMOVD2M", Family: asm.FamilyMask, LaneBits: 32, Effect: asm.EffectWriteOnly, LLVMOp: "v2m"},
	{Op: "VPMOVQ2M", Family: asm.FamilyMask, LaneBits: 64, Effect: asm.EffectWriteOnly, LLVMOp: "v2m"},
	{Op: "VPMOVM2B", Family: asm.FamilyMask, LaneBits: 8, Effect: asm.EffectWriteZeroUpper, LLVMOp: "m2v"},
	{Op: "VPMOVM2W", Family: asm.FamilyMask, LaneBits: 16, Effect: asm.EffectWriteZeroUpper, LLVMOp: "m2v"},
	{Op: "VPMOVM2D", Family: asm.FamilyMask, LaneBits: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "m2v"},
	{Op: "VPMOVM2Q", Family: asm.FamilyMask, LaneBits: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "m2v"},

	// Narrowing VPMOV{,S,US} (SubOp: 0=trunc, 1=signed-sat, 2=unsigned-sat)
	{Op: "VPMOVWB", Family: asm.FamilyVecUnary, SubOp: 0, SrcWidth: 16, Width: 8, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpmov_narrow"},
	{Op: "VPMOVDB", Family: asm.FamilyVecUnary, SubOp: 0, SrcWidth: 32, Width: 8, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpmov_narrow"},
	{Op: "VPMOVDW", Family: asm.FamilyVecUnary, SubOp: 0, SrcWidth: 32, Width: 16, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpmov_narrow"},
	{Op: "VPMOVQB", Family: asm.FamilyVecUnary, SubOp: 0, SrcWidth: 64, Width: 8, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpmov_narrow"},
	{Op: "VPMOVQW", Family: asm.FamilyVecUnary, SubOp: 0, SrcWidth: 64, Width: 16, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpmov_narrow"},
	{Op: "VPMOVQD", Family: asm.FamilyVecUnary, SubOp: 0, SrcWidth: 64, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpmov_narrow"},
	{Op: "VPMOVSWB", Family: asm.FamilyVecUnary, SubOp: 1, SrcWidth: 16, Width: 8, Signed: true, Saturating: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpmov_narrow"},
	{Op: "VPMOVSDB", Family: asm.FamilyVecUnary, SubOp: 1, SrcWidth: 32, Width: 8, Signed: true, Saturating: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpmov_narrow"},
	{Op: "VPMOVSDW", Family: asm.FamilyVecUnary, SubOp: 1, SrcWidth: 32, Width: 16, Signed: true, Saturating: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpmov_narrow"},
	{Op: "VPMOVSQB", Family: asm.FamilyVecUnary, SubOp: 1, SrcWidth: 64, Width: 8, Signed: true, Saturating: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpmov_narrow"},
	{Op: "VPMOVSQW", Family: asm.FamilyVecUnary, SubOp: 1, SrcWidth: 64, Width: 16, Signed: true, Saturating: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpmov_narrow"},
	{Op: "VPMOVSQD", Family: asm.FamilyVecUnary, SubOp: 1, SrcWidth: 64, Width: 32, Signed: true, Saturating: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpmov_narrow"},
	{Op: "VPMOVUSWB", Family: asm.FamilyVecUnary, SubOp: 2, SrcWidth: 16, Width: 8, Saturating: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpmov_narrow"},
	{Op: "VPMOVUSDB", Family: asm.FamilyVecUnary, SubOp: 2, SrcWidth: 32, Width: 8, Saturating: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpmov_narrow"},
	{Op: "VPMOVUSDW", Family: asm.FamilyVecUnary, SubOp: 2, SrcWidth: 32, Width: 16, Saturating: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpmov_narrow"},
	{Op: "VPMOVUSQB", Family: asm.FamilyVecUnary, SubOp: 2, SrcWidth: 64, Width: 8, Saturating: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpmov_narrow"},
	{Op: "VPMOVUSQW", Family: asm.FamilyVecUnary, SubOp: 2, SrcWidth: 64, Width: 16, Saturating: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpmov_narrow"},
	{Op: "VPMOVUSQD", Family: asm.FamilyVecUnary, SubOp: 2, SrcWidth: 64, Width: 32, Saturating: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpmov_narrow"},

	// Horizontal int add/sub (12 ops)
	{Op: "PHADDW", Family: asm.FamilyVecShuffle, LaneBits: 16, Effect: asm.EffectReadWrite, LLVMOp: "hadd"},
	{Op: "PHADDD", Family: asm.FamilyVecShuffle, LaneBits: 32, Effect: asm.EffectReadWrite, LLVMOp: "hadd"},
	{Op: "PHADDSW", Family: asm.FamilyVecShuffle, LaneBits: 16, Signed: true, Saturating: true, Effect: asm.EffectReadWrite, LLVMOp: "hadd"},
	{Op: "PHSUBW", Family: asm.FamilyVecShuffle, LaneBits: 16, Effect: asm.EffectReadWrite, LLVMOp: "hsub"},
	{Op: "PHSUBD", Family: asm.FamilyVecShuffle, LaneBits: 32, Effect: asm.EffectReadWrite, LLVMOp: "hsub"},
	{Op: "PHSUBSW", Family: asm.FamilyVecShuffle, LaneBits: 16, Signed: true, Saturating: true, Effect: asm.EffectReadWrite, LLVMOp: "hsub"},
	{Op: "VPHADDW", Family: asm.FamilyVecShuffle, LaneBits: 16, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "hadd"},
	{Op: "VPHADDD", Family: asm.FamilyVecShuffle, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "hadd"},
	{Op: "VPHADDSW", Family: asm.FamilyVecShuffle, LaneBits: 16, Signed: true, Saturating: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "hadd"},
	{Op: "VPHSUBW", Family: asm.FamilyVecShuffle, LaneBits: 16, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "hsub"},
	{Op: "VPHSUBD", Family: asm.FamilyVecShuffle, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "hsub"},
	{Op: "VPHSUBSW", Family: asm.FamilyVecShuffle, LaneBits: 16, Signed: true, Saturating: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "hsub"},

	// Multiply-add, MulHrs, IFMA52, VNNI dot-products (14 ops)
	{Op: "PMADDWL", Family: asm.FamilyVecFMA, LaneBits: 16, Signed: true, Effect: asm.EffectReadWrite, LLVMOp: "pmaddwd"},
	{Op: "VPMADDWD", Family: asm.FamilyVecFMA, LaneBits: 16, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "pmaddwd"},
	{Op: "PMADDUBSW", Family: asm.FamilyVecFMA, LaneBits: 8, Saturating: true, Effect: asm.EffectReadWrite, LLVMOp: "pmaddubsw"},
	{Op: "VPMADDUBSW", Family: asm.FamilyVecFMA, LaneBits: 8, Saturating: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "pmaddubsw"},
	{Op: "PMULHRSW", Family: asm.FamilyVecFMA, LaneBits: 16, Signed: true, Effect: asm.EffectReadWrite, LLVMOp: "pmulhrsw"},
	{Op: "VPMULHRSW", Family: asm.FamilyVecFMA, LaneBits: 16, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "pmulhrsw"},
	{Op: "VPMADD52LUQ", Family: asm.FamilyVecFMA, SubOp: 0, LaneBits: 64, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "pmadd52"},
	{Op: "VPMADD52HUQ", Family: asm.FamilyVecFMA, SubOp: 1, LaneBits: 64, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "pmadd52"},
	{Op: "VPDPBUSD", Family: asm.FamilyVecFMA, SubOp: 0, LaneBits: 8, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "vpdp"},
	{Op: "VPDPBUSDS", Family: asm.FamilyVecFMA, SubOp: 1, LaneBits: 8, Saturating: true, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "vpdp"},
	{Op: "VPDPWSSD", Family: asm.FamilyVecFMA, SubOp: 0, LaneBits: 16, Signed: true, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "vpdp"},
	{Op: "VPDPWSSDS", Family: asm.FamilyVecFMA, SubOp: 1, LaneBits: 16, Signed: true, Saturating: true, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "vpdp"},
	{Op: "VP4DPWSSD", Family: asm.FamilyVecFMA, SubOp: 0, LaneBits: 16, Signed: true, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "vp4dp"},
	{Op: "VP4DPWSSDS", Family: asm.FamilyVecFMA, SubOp: 1, LaneBits: 16, Signed: true, Saturating: true, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "vp4dp"},

	// Funnel shifts (12 ops)
	{Op: "VPSHLDW", Family: asm.FamilyVecShift, SubOp: 0, LaneBits: 16, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "funnel_imm"},
	{Op: "VPSHLDD", Family: asm.FamilyVecShift, SubOp: 0, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "funnel_imm"},
	{Op: "VPSHLDQ", Family: asm.FamilyVecShift, SubOp: 0, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "funnel_imm"},
	{Op: "VPSHRDW", Family: asm.FamilyVecShift, SubOp: 1, LaneBits: 16, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "funnel_imm"},
	{Op: "VPSHRDD", Family: asm.FamilyVecShift, SubOp: 1, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "funnel_imm"},
	{Op: "VPSHRDQ", Family: asm.FamilyVecShift, SubOp: 1, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "funnel_imm"},
	{Op: "VPSHLDVW", Family: asm.FamilyVecShift, SubOp: 0, LaneBits: 16, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "funnel_var"},
	{Op: "VPSHLDVD", Family: asm.FamilyVecShift, SubOp: 0, LaneBits: 32, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "funnel_var"},
	{Op: "VPSHLDVQ", Family: asm.FamilyVecShift, SubOp: 0, LaneBits: 64, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "funnel_var"},
	{Op: "VPSHRDVW", Family: asm.FamilyVecShift, SubOp: 1, LaneBits: 16, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "funnel_var"},
	{Op: "VPSHRDVD", Family: asm.FamilyVecShift, SubOp: 1, LaneBits: 32, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "funnel_var"},
	{Op: "VPSHRDVQ", Family: asm.FamilyVecShift, SubOp: 1, LaneBits: 64, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "funnel_var"},

	// SAD / Multishift (4 ops)
	{Op: "MPSADBW", Family: asm.FamilyVecShuffle, LaneBits: 8, Effect: asm.EffectReadWrite, LLVMOp: "mpsadbw"},
	{Op: "VMPSADBW", Family: asm.FamilyVecShuffle, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "mpsadbw"},
	{Op: "VDBPSADBW", Family: asm.FamilyVecShuffle, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "dbpsadbw"},
	{Op: "VPMULTISHIFTQB", Family: asm.FamilyVecShuffle, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "multishiftqb"},

	// Family 4: Vec Compare & Test (15 ops)
	{Op: "VCMPPS", Family: asm.FamilyCompare, SubOp: 0, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vcmpfp"},
	{Op: "VCMPPD", Family: asm.FamilyCompare, SubOp: 0, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vcmpfp"},
	{Op: "VCMPSS", Family: asm.FamilyCompare, SubOp: 1, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vcmpfp"},
	{Op: "VCMPSD", Family: asm.FamilyCompare, SubOp: 1, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vcmpfp"},
	{Op: "VPTESTMB", Family: asm.FamilyCompare, SubOp: 0, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "vptestm"},
	{Op: "VPTESTMW", Family: asm.FamilyCompare, SubOp: 0, LaneBits: 16, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "vptestm"},
	{Op: "VPTESTMD", Family: asm.FamilyCompare, SubOp: 0, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "vptestm"},
	{Op: "VPTESTMQ", Family: asm.FamilyCompare, SubOp: 0, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "vptestm"},
	{Op: "VPTESTNMB", Family: asm.FamilyCompare, SubOp: 1, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "vptestm"},
	{Op: "VPTESTNMW", Family: asm.FamilyCompare, SubOp: 1, LaneBits: 16, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "vptestm"},
	{Op: "VPTESTNMD", Family: asm.FamilyCompare, SubOp: 1, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "vptestm"},
	{Op: "VPTESTNMQ", Family: asm.FamilyCompare, SubOp: 1, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "vptestm"},
	{Op: "PTEST", Family: asm.FamilyCompare, LaneBits: 8, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite, LLVMOp: "ptest"},
	{Op: "VTESTPS", Family: asm.FamilyCompare, LaneBits: 32, Float: true, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite, LLVMOp: "vtestfp"},
	{Op: "VTESTPD", Family: asm.FamilyCompare, LaneBits: 64, Float: true, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite, LLVMOp: "vtestfp"},

	// Family 5: Gather & Scatter (16 ops; SrcWidth=index bits 32/64, Width=data bits 32/64, Float=FP)
	{Op: "VGATHERDPS", Family: asm.FamilyMove, SubOp: 0, SrcWidth: 32, Width: 32, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "gather"},
	{Op: "VGATHERDPD", Family: asm.FamilyMove, SubOp: 0, SrcWidth: 32, Width: 64, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "gather"},
	{Op: "VGATHERQPS", Family: asm.FamilyMove, SubOp: 0, SrcWidth: 64, Width: 32, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "gather"},
	{Op: "VGATHERQPD", Family: asm.FamilyMove, SubOp: 0, SrcWidth: 64, Width: 64, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "gather"},
	{Op: "VPGATHERDD", Family: asm.FamilyMove, SubOp: 0, SrcWidth: 32, Width: 32, Effect: asm.EffectReadWrite, LLVMOp: "gather"},
	{Op: "VPGATHERDQ", Family: asm.FamilyMove, SubOp: 0, SrcWidth: 32, Width: 64, Effect: asm.EffectReadWrite, LLVMOp: "gather"},
	{Op: "VPGATHERQD", Family: asm.FamilyMove, SubOp: 0, SrcWidth: 64, Width: 32, Effect: asm.EffectReadWrite, LLVMOp: "gather"},
	{Op: "VPGATHERQQ", Family: asm.FamilyMove, SubOp: 0, SrcWidth: 64, Width: 64, Effect: asm.EffectReadWrite, LLVMOp: "gather"},
	{Op: "VSCATTERDPS", Family: asm.FamilyMove, SubOp: 1, SrcWidth: 32, Width: 32, Float: true, Effect: asm.EffectReadOnly, LLVMOp: "scatter"},
	{Op: "VSCATTERDPD", Family: asm.FamilyMove, SubOp: 1, SrcWidth: 32, Width: 64, Float: true, Effect: asm.EffectReadOnly, LLVMOp: "scatter"},
	{Op: "VSCATTERQPS", Family: asm.FamilyMove, SubOp: 1, SrcWidth: 64, Width: 32, Float: true, Effect: asm.EffectReadOnly, LLVMOp: "scatter"},
	{Op: "VSCATTERQPD", Family: asm.FamilyMove, SubOp: 1, SrcWidth: 64, Width: 64, Float: true, Effect: asm.EffectReadOnly, LLVMOp: "scatter"},
	{Op: "VPSCATTERDD", Family: asm.FamilyMove, SubOp: 1, SrcWidth: 32, Width: 32, Effect: asm.EffectReadOnly, LLVMOp: "scatter"},
	{Op: "VPSCATTERDQ", Family: asm.FamilyMove, SubOp: 1, SrcWidth: 32, Width: 64, Effect: asm.EffectReadOnly, LLVMOp: "scatter"},
	{Op: "VPSCATTERQD", Family: asm.FamilyMove, SubOp: 1, SrcWidth: 64, Width: 32, Effect: asm.EffectReadOnly, LLVMOp: "scatter"},
	{Op: "VPSCATTERQQ", Family: asm.FamilyMove, SubOp: 1, SrcWidth: 64, Width: 64, Effect: asm.EffectReadOnly, LLVMOp: "scatter"},

	// Family 6: Permute / Expand / Conflict / LZCNT / Rotate / Subvec-Broadcast / K-Test (52 ops)
	{Op: "VPLZCNTD", Family: asm.FamilyVecUnary, LaneBits: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vplzcnt"},
	{Op: "VPLZCNTQ", Family: asm.FamilyVecUnary, LaneBits: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vplzcnt"},
	{Op: "VPROLVD", Family: asm.FamilyVecShift, SubOp: 0, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vrot_var"},
	{Op: "VPROLVQ", Family: asm.FamilyVecShift, SubOp: 0, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vrot_var"},
	{Op: "VPRORVD", Family: asm.FamilyVecShift, SubOp: 1, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vrot_var"},
	{Op: "VPRORVQ", Family: asm.FamilyVecShift, SubOp: 1, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vrot_var"},

	{Op: "VPERMW", Family: asm.FamilyVecShuffle, LaneBits: 16, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vperm1"},
	{Op: "VPERMD", Family: asm.FamilyVecShuffle, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vperm1"},
	{Op: "VPERMPS", Family: asm.FamilyVecShuffle, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vperm1"},
	{Op: "VPERMI2W", Family: asm.FamilyVecShuffle, SubOp: 0, LaneBits: 16, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "vperm2"},
	{Op: "VPERMI2D", Family: asm.FamilyVecShuffle, SubOp: 0, LaneBits: 32, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "vperm2"},
	{Op: "VPERMI2Q", Family: asm.FamilyVecShuffle, SubOp: 0, LaneBits: 64, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "vperm2"},
	{Op: "VPERMI2PS", Family: asm.FamilyVecShuffle, SubOp: 0, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "vperm2"},
	{Op: "VPERMI2PD", Family: asm.FamilyVecShuffle, SubOp: 0, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "vperm2"},
	{Op: "VPERMT2B", Family: asm.FamilyVecShuffle, SubOp: 1, LaneBits: 8, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "vperm2"},
	{Op: "VPERMT2W", Family: asm.FamilyVecShuffle, SubOp: 1, LaneBits: 16, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "vperm2"},
	{Op: "VPERMT2D", Family: asm.FamilyVecShuffle, SubOp: 1, LaneBits: 32, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "vperm2"},
	{Op: "VPERMT2Q", Family: asm.FamilyVecShuffle, SubOp: 1, LaneBits: 64, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "vperm2"},
	{Op: "VPERMT2PS", Family: asm.FamilyVecShuffle, SubOp: 1, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "vperm2"},
	{Op: "VPERMT2PD", Family: asm.FamilyVecShuffle, SubOp: 1, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "vperm2"},

	{Op: "VPEXPANDB", Family: asm.FamilyVecShuffle, LaneBits: 8, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vexpand"},
	{Op: "VPEXPANDW", Family: asm.FamilyVecShuffle, LaneBits: 16, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vexpand"},
	{Op: "VPEXPANDD", Family: asm.FamilyVecShuffle, LaneBits: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vexpand"},
	{Op: "VPEXPANDQ", Family: asm.FamilyVecShuffle, LaneBits: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vexpand"},
	{Op: "VEXPANDPS", Family: asm.FamilyVecShuffle, LaneBits: 32, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vexpand"},
	{Op: "VEXPANDPD", Family: asm.FamilyVecShuffle, LaneBits: 64, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vexpand"},

	{Op: "VPCONFLICTD", Family: asm.FamilyVecUnary, LaneBits: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpconflict"},
	{Op: "VPCONFLICTQ", Family: asm.FamilyVecUnary, LaneBits: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpconflict"},

	{Op: "VBROADCASTF128", Family: asm.FamilyVecUnary, Width: 128, LaneBits: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vbcast_sub"},
	{Op: "VBROADCASTF32X4", Family: asm.FamilyVecUnary, Width: 128, LaneBits: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vbcast_sub"},
	{Op: "VBROADCASTF32X8", Family: asm.FamilyVecUnary, Width: 256, LaneBits: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vbcast_sub"},
	{Op: "VBROADCASTF64X2", Family: asm.FamilyVecUnary, Width: 128, LaneBits: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vbcast_sub"},
	{Op: "VBROADCASTF64X4", Family: asm.FamilyVecUnary, Width: 256, LaneBits: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vbcast_sub"},
	{Op: "VBROADCASTI32X2", Family: asm.FamilyVecUnary, Width: 64, LaneBits: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vbcast_sub"},
	{Op: "VBROADCASTI32X4", Family: asm.FamilyVecUnary, Width: 128, LaneBits: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vbcast_sub"},
	{Op: "VBROADCASTI32X8", Family: asm.FamilyVecUnary, Width: 256, LaneBits: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vbcast_sub"},
	{Op: "VBROADCASTI64X2", Family: asm.FamilyVecUnary, Width: 128, LaneBits: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vbcast_sub"},
	{Op: "VBROADCASTI64X4", Family: asm.FamilyVecUnary, Width: 256, LaneBits: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vbcast_sub"},
	{Op: "VPBROADCASTMB2Q", Family: asm.FamilyVecUnary, SrcWidth: 8, LaneBits: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpbcast_m"},
	{Op: "VPBROADCASTMW2D", Family: asm.FamilyVecUnary, SrcWidth: 16, LaneBits: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpbcast_m"},

	{Op: "KTESTB", Family: asm.FamilyMask, SubOp: 0, Width: 8, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite, LLVMOp: "ktest"},
	{Op: "KTESTW", Family: asm.FamilyMask, SubOp: 0, Width: 16, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite, LLVMOp: "ktest"},
	{Op: "KTESTD", Family: asm.FamilyMask, SubOp: 0, Width: 32, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite, LLVMOp: "ktest"},
	{Op: "KTESTQ", Family: asm.FamilyMask, SubOp: 0, Width: 64, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite, LLVMOp: "ktest"},
	{Op: "KORTESTB", Family: asm.FamilyMask, SubOp: 1, Width: 8, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite, LLVMOp: "ktest"},
	{Op: "KORTESTW", Family: asm.FamilyMask, SubOp: 1, Width: 16, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite, LLVMOp: "ktest"},
	{Op: "KORTESTD", Family: asm.FamilyMask, SubOp: 1, Width: 32, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite, LLVMOp: "ktest"},
	{Op: "KORTESTQ", Family: asm.FamilyMask, SubOp: 1, Width: 64, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite, LLVMOp: "ktest"},
	{Op: "KUNPCKBW", Family: asm.FamilyMask, Width: 8, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "kunpck"},
	{Op: "KUNPCKWD", Family: asm.FamilyMask, Width: 16, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "kunpck"},
	{Op: "KUNPCKDQ", Family: asm.FamilyMask, Width: 32, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "kunpck"},
	{Op: "VPSHUFBITQMB", Family: asm.FamilyCompare, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "vpshufbitqmb"},
}

var x86M2VecExtTable = asm.NewOpTable(x86M2VecExtSpecs)

func (c *amd64Ctx) lowerM2VecExt(op asm.Op, ins asm.Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(ins.Op))
	zeroMask := strings.Contains(rawOp, ".Z")
	bcst := strings.Contains(rawOp, ".BCST")
	baseOp := op
	if dot := strings.IndexByte(string(baseOp), '.'); dot >= 0 {
		baseOp = asm.Op(string(baseOp)[:dot])
	}
	spec, found := x86M2VecExtTable.Lookup(baseOp)
	if !found {
		return false, false, nil
	}
	switch spec.LLVMOp {
	case "pshufw_mmx":
		return true, false, c.lowerX86PSHUFWMMX(ins)
	case "v2m", "m2v":
		return true, false, c.lowerX86VPMOVMask(spec, ins)
	case "vpmov_narrow":
		return true, false, c.lowerX86VPMOVNarrow(spec, zeroMask, ins)
	case "hadd", "hsub":
		return true, false, c.lowerX86PHAddSub(spec, ins)
	case "pmaddwd", "pmaddubsw", "pmulhrsw", "pmadd52", "vpdp", "vp4dp":
		return true, false, c.lowerX86PMAddDP(spec, zeroMask, bcst, ins)
	case "funnel_imm", "funnel_var", "vrot_var":
		return true, false, c.lowerX86FunnelRot(spec, zeroMask, bcst, ins)
	case "mpsadbw", "dbpsadbw", "multishiftqb":
		return true, false, c.lowerX86SADMultiShift(spec, zeroMask, bcst, ins)
	case "vcmpfp":
		return true, false, c.lowerX86VCMPFP(spec, bcst, ins)
	case "vptestm":
		return true, false, c.lowerX86VPTESTM(spec, bcst, ins)
	case "ptest", "vtestfp":
		return true, false, c.lowerX86PTEST(spec, ins)
	case "gather", "scatter":
		return true, false, c.lowerX86GatherScatter(spec, ins)
	case "vplzcnt":
		return true, false, c.lowerX86VPLZCNT(spec, zeroMask, bcst, ins)
	case "vperm1", "vperm2":
		return true, false, c.lowerX86VPerm(spec, zeroMask, bcst, ins)
	case "vexpand":
		return true, false, c.lowerX86VExpand(spec, zeroMask, ins)
	case "vpconflict":
		return true, false, c.lowerX86VPConflict(spec, zeroMask, bcst, ins)
	case "vbcast_sub":
		return true, false, c.lowerX86VBcastSub(spec, zeroMask, ins)
	case "vpbcast_m":
		return true, false, c.lowerX86VPBcastM(spec, ins)
	case "ktest", "kunpck":
		return true, false, c.lowerX86KTestUnpck(spec, ins)
	case "vpshufbitqmb":
		return true, false, c.lowerX86VPShufBitQMB(ins)
	}
	return false, false, nil
}

func (c *amd64Ctx) lowerX86PSHUFWMMX(ins asm.Instr) error {
	if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpImm || ins.Args[2].Kind != asm.OpReg || !isAMD64MReg(ins.Args[2].Reg) {
		return fmt.Errorf("amd64 PSHUFW expects $imm, src, Mdst: %q", ins.Raw)
	}
	src, err := c.loadMVecOperand(ins.Args[1])
	if err != nil {
		return err
	}
	imm := ins.Args[0].Imm
	bc, sh, out := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <8 x i8> %s to <4 x i16>\n", bc, src)
	fmt.Fprintf(c.b, "  %%%s = shufflevector <4 x i16> %%%s, <4 x i16> poison, <4 x i32> <i32 %d, i32 %d, i32 %d, i32 %d>\n",
		sh, bc, imm&3, (imm>>2)&3, (imm>>4)&3, (imm>>6)&3)
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i16> %%%s to <8 x i8>\n", out, sh)
	return c.storeM(ins.Args[2].Reg, "%"+out)
}

func (c *amd64Ctx) lowerX86VPMOVMask(spec asm.OpSpec, ins asm.Instr) error {
	if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg {
		return fmt.Errorf("amd64 %s expects srcReg, dstReg: %q", spec.Op, ins.Raw)
	}
	laneBits := int(spec.LaneBits)
	elemTy := fmt.Sprintf("i%d", laneBits)
	if spec.LLVMOp == "v2m" {
		if !isAMD64KReg(ins.Args[1].Reg) {
			return fmt.Errorf("amd64 %s expects Kdst: %q", spec.Op, ins.Raw)
		}
		vi, ok := c.x86VecInfoForReg(ins.Args[0].Reg)
		if !ok {
			return fmt.Errorf("amd64 %s expects vector src: %q", spec.Op, ins.Raw)
		}
		raw, err := vi.loadReg(ins.Args[0].Reg)
		if err != nil {
			return err
		}
		lanes := vi.totalBits / laneBits
		vecTy := fmt.Sprintf("<%d x %s>", lanes, elemTy)
		bc, cmp := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bc, vi.byteVecTy, raw, vecTy)
		fmt.Fprintf(c.b, "  %%%s = icmp slt %s %%%s, zeroinitializer\n", cmp, vecTy, bc)
		return c.storeK(ins.Args[1].Reg, c.x86PackI1VecToK("%"+cmp, lanes))
	}
	// m2v: Ksrc -> Vdst
	if !isAMD64KReg(ins.Args[0].Reg) {
		return fmt.Errorf("amd64 %s expects Ksrc: %q", spec.Op, ins.Raw)
	}
	vi, ok := c.x86VecInfoForReg(ins.Args[1].Reg)
	if !ok {
		return fmt.Errorf("amd64 %s expects vector dst: %q", spec.Op, ins.Raw)
	}
	lanes := vi.totalBits / laneBits
	vecTy := fmt.Sprintf("<%d x %s>", lanes, elemTy)
	mvec, err := c.x86KToI1Vec(ins.Args[0].Reg, lanes)
	if err != nil {
		return err
	}
	sext, out := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sext <%d x i1> %s to %s\n", sext, lanes, mvec, vecTy)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to %s\n", out, vecTy, sext, vi.byteVecTy)
	return vi.storeVec(ins.Args[1].Reg, "%"+out)
}

func (c *amd64Ctx) lowerX86VPMOVNarrow(spec asm.OpSpec, zeroMask bool, ins asm.Instr) error {
	args, kreg, hasMask := x86StripEVEXMask(ins.Args)
	if len(args) != 2 || args[0].Kind != asm.OpReg {
		return fmt.Errorf("amd64 %s expects Vsrc, [K,] dst: %q", spec.Op, ins.Raw)
	}
	svi, ok := c.x86VecInfoForReg(args[0].Reg)
	if !ok {
		return fmt.Errorf("amd64 %s requires vector src: %q", spec.Op, ins.Raw)
	}
	srcBits, dstBits := int(spec.SrcWidth), int(spec.Width)
	lanes := svi.totalBits / srcBits
	srcTy := fmt.Sprintf("<%d x i%d>", lanes, srcBits)
	dstTy := fmt.Sprintf("<%d x i%d>", lanes, dstBits)
	raw, err := svi.loadReg(args[0].Reg)
	if err != nil {
		return err
	}
	bc := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bc, svi.byteVecTy, raw, srcTy)
	val := "%" + bc
	if spec.SubOp == 1 {
		// Signed saturation to [-2^(dstBits-1), 2^(dstBits-1)-1]
		loVal := -(int64(1) << uint(dstBits-1))
		hiVal := (int64(1) << uint(dstBits-1)) - 1
		loSplat := x86IntSplat(lanes, srcBits, loVal)
		hiSplat := x86IntSplat(lanes, srcBits, hiVal)
		cLo, sLo, cHi, sHi := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, %s\n", cLo, srcTy, val, loSplat)
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %s\n", sLo, lanes, cLo, srcTy, loSplat, srcTy, val)
		fmt.Fprintf(c.b, "  %%%s = icmp sgt %s %%%s, %s\n", cHi, srcTy, sLo, hiSplat)
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %%%s\n", sHi, lanes, cHi, srcTy, hiSplat, srcTy, sLo)
		val = "%" + sHi
	} else if spec.SubOp == 2 {
		// Unsigned saturation to [0, 2^dstBits - 1]
		hiVal := (int64(1) << uint(dstBits)) - 1
		hiSplat := x86IntSplat(lanes, srcBits, hiVal)
		cHi, sHi := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ugt %s %s, %s\n", cHi, srcTy, val, hiSplat)
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %s\n", sHi, lanes, cHi, srcTy, hiSplat, srcTy, val)
		val = "%" + sHi
	}
	tr := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc %s %s to %s\n", tr, srcTy, val, dstTy)
	res := "%" + tr

	dstOp := args[1]
	if dstOp.Kind == asm.OpReg {
		dvi, ok := c.x86VecInfoForReg(dstOp.Reg)
		if !ok {
			return fmt.Errorf("amd64 %s dst must be vector reg or mem: %q", spec.Op, ins.Raw)
		}
		dstFullLanes := dvi.totalBits / dstBits
		dstFullTy := fmt.Sprintf("<%d x i%d>", dstFullLanes, dstBits)
		if hasMask {
			oldB, err := dvi.loadReg(dstOp.Reg)
			if err != nil {
				return err
			}
			oldFull := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", oldFull, dvi.byteVecTy, oldB, dstFullTy)
			oldN := "%" + oldFull
			if lanes < dstFullLanes {
				sh := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s zeroinitializer, <%d x i32> %s\n",
					sh, dstFullTy, oldFull, dstFullTy, lanes, llvmI32RangeMask(0, lanes))
				oldN = "%" + sh
			}
			res, err = c.x86ApplyMask(kreg, zeroMask, lanes, dstTy, res, oldN)
			if err != nil {
				return err
			}
		}
		if lanes < dstFullLanes {
			pad := c.newTmp()
			me := make([]string, dstFullLanes)
			for i := 0; i < dstFullLanes; i++ {
				if i < lanes {
					me[i] = fmt.Sprintf("i32 %d", i)
				} else {
					me[i] = fmt.Sprintf("i32 %d", lanes)
				}
			}
			fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s zeroinitializer, <%d x i32> <%s>\n",
				pad, dstTy, res, dstTy, dstFullLanes, strings.Join(me, ", "))
			res = "%" + pad
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, dstFullTy, res, dvi.byteVecTy)
		return dvi.storeVec(dstOp.Reg, "%"+out)
	}
	var p, pty string
	switch dstOp.Kind {
	case asm.OpMem:
		p, pty, err = c.ptrFromMem(dstOp.Mem)
	case asm.OpSym:
		p, err = c.ptrFromSB(dstOp.Sym)
		pty = "ptr"
	default:
		return fmt.Errorf("amd64 %s unsupported dst %s: %q", spec.Op, dstOp.String(), ins.Raw)
	}
	if err != nil {
		return err
	}
	if hasMask {
		mv, err := c.x86KToI1Vec(kreg, lanes)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  call void @llvm.masked.store.v%di%d.p0(%s %s, %s %s, i32 1, <%d x i1> %s)\n",
			lanes, dstBits, dstTy, res, pty, p, lanes, mv)
		return nil
	}
	fmt.Fprintf(c.b, "  store %s %s, %s %s, align 1\n", dstTy, res, pty, p)
	return nil
}

func (c *amd64Ctx) lowerX86PHAddSub(spec asm.OpSpec, ins asm.Instr) error {
	var srcOp, lhsOp, dstOp asm.Operand
	if spec.ThreeOp {
		if len(ins.Args) != 3 || ins.Args[2].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects src, lhs, dst: %q", spec.Op, ins.Raw)
		}
		srcOp, lhsOp, dstOp = ins.Args[0], ins.Args[1], ins.Args[2]
	} else {
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects src, dst: %q", spec.Op, ins.Raw)
		}
		srcOp, lhsOp, dstOp = ins.Args[0], ins.Args[1], ins.Args[1]
	}
	vi, ok := c.x86VecInfoForReg(dstOp.Reg)
	if !ok {
		return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
	}
	laneBits := int(spec.LaneBits)
	lanes := vi.totalBits / laneBits
	vecTy := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
	aRaw, err := vi.loadVec(lhsOp)
	if err != nil {
		return err
	}
	bRaw, err := vi.loadVec(srcOp)
	if err != nil {
		return err
	}
	ab, bb := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", ab, vi.byteVecTy, aRaw, vecTy)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bb, vi.byteVecTy, bRaw, vecTy)

	// Build even/odd shuffle masks per 128-bit lane (or 64-bit MMX lane).
	chunkLanes := lanes
	if vi.totalBits >= 128 {
		chunkLanes = 128 / laneBits
	}
	evenM := make([]string, lanes)
	oddM := make([]string, lanes)
	for base := 0; base < lanes; base += chunkLanes {
		half := chunkLanes / 2
		for j := 0; j < half; j++ {
			evenM[base+j] = fmt.Sprintf("i32 %d", base+2*j)
			oddM[base+j] = fmt.Sprintf("i32 %d", base+2*j+1)
			evenM[base+half+j] = fmt.Sprintf("i32 %d", lanes+base+2*j)
			oddM[base+half+j] = fmt.Sprintf("i32 %d", lanes+base+2*j+1)
		}
	}
	ev, od, res, out := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s %%%s, <%d x i32> <%s>\n", ev, vecTy, ab, vecTy, bb, lanes, strings.Join(evenM, ", "))
	fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s %%%s, <%d x i32> <%s>\n", od, vecTy, ab, vecTy, bb, lanes, strings.Join(oddM, ", "))
	switch {
	case spec.LLVMOp == "hadd" && spec.Saturating:
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.sadd.sat.v%di%d(%s %%%s, %s %%%s)\n", res, vecTy, lanes, laneBits, vecTy, ev, vecTy, od)
	case spec.LLVMOp == "hsub" && spec.Saturating:
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.ssub.sat.v%di%d(%s %%%s, %s %%%s)\n", res, vecTy, lanes, laneBits, vecTy, ev, vecTy, od)
	case spec.LLVMOp == "hadd":
		fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", res, vecTy, ev, od)
	default:
		fmt.Fprintf(c.b, "  %%%s = sub %s %%%s, %%%s\n", res, vecTy, ev, od)
	}
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to %s\n", out, vecTy, res, vi.byteVecTy)
	return vi.storeVec(dstOp.Reg, "%"+out)
}

func (c *amd64Ctx) lowerX86PMAddDP(spec asm.OpSpec, zeroMask, bcst bool, ins asm.Instr) error {
	args, kreg, hasMask := x86StripEVEXMask(ins.Args)
	if spec.LLVMOp == "vp4dp" {
		// VP4DPWSSD[S] mem128, [Z0-Z3] or Z0, [K,] Zdst
		regList := x86Expand4RegGroup(args[1])
		if len(args) != 3 || len(regList) == 0 || args[2].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects mem, [reg-list], [K,] Zdst: %q", spec.Op, ins.Raw)
		}
		vi, ok := c.x86VecInfoForReg(args[2].Reg)
		if !ok {
			return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
		}
		p, pty, err := c.ptrFromMem(args[0].Mem)
		if err != nil {
			return err
		}
		ld := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load <4 x i32>, %s %s, align 1\n", ld, pty, p)
		lanes := vi.totalBits / 32
		vecTy := fmt.Sprintf("<%d x i32>", lanes)
		oldB, err := vi.loadReg(args[2].Reg)
		if err != nil {
			return err
		}
		accBC := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", accBC, vi.byteVecTy, oldB, vecTy)
		acc := "%" + accBC
		oldD := acc
		for i, r := range regList {
			if i >= 4 {
				break
			}
			rvi, ok := c.x86VecInfoForReg(r)
			if !ok {
				return fmt.Errorf("amd64 %s invalid list reg %s: %q", spec.Op, r, ins.Raw)
			}
			rb, err := rvi.loadReg(r)
			if err != nil {
				return err
			}
			w32, s0, sp, spW := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <4 x i32> %%%s, i32 %d\n", w32, ld, i)
			fmt.Fprintf(c.b, "  %%%s = insertelement %s undef, i32 %%%s, i32 0\n", s0, vecTy, w32)
			fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <%d x i32> zeroinitializer\n", sp, vecTy, s0, vecTy, lanes)
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to %s\n", spW, vecTy, sp, vi.byteVecTy)
			prod := c.emitPMAddWD(vi.totalBits, rb, "%"+spW)
			nxt := c.newTmp()
			if spec.Saturating {
				fmt.Fprintf(c.b, "  %%%s = call %s @llvm.sadd.sat.v%di32(%s %s, %s %s)\n", nxt, vecTy, lanes, vecTy, acc, vecTy, prod)
			} else {
				fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", nxt, vecTy, acc, prod)
			}
			acc = "%" + nxt
		}
		if hasMask {
			acc, err = c.x86ApplyMask(kreg, zeroMask, lanes, vecTy, acc, oldD)
			if err != nil {
				return err
			}
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, vecTy, acc, vi.byteVecTy)
		return vi.storeVec(args[2].Reg, "%"+out)
	}

	var srcOp, lhsOp, dstOp asm.Operand
	if spec.ThreeOp {
		if len(args) != 3 || args[2].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects src, lhs, [K,] dst: %q", spec.Op, ins.Raw)
		}
		srcOp, lhsOp, dstOp = args[0], args[1], args[2]
	} else {
		if len(args) != 2 || args[1].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects src, dst: %q", spec.Op, ins.Raw)
		}
		srcOp, lhsOp, dstOp = args[0], args[1], args[1]
	}
	vi, ok := c.x86VecInfoForReg(dstOp.Reg)
	if !ok {
		return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
	}
	bcstBits := 32
	if spec.LaneBits == 64 {
		bcstBits = 64
	}
	bRaw, err := c.x86LoadVecOrBcst(vi, srcOp, bcst, bcstBits)
	if err != nil {
		return err
	}
	aRaw, err := vi.loadVec(lhsOp)
	if err != nil {
		return err
	}
	var resVec, resVecTy string
	var maskLanes int
	switch spec.LLVMOp {
	case "pmaddwd":
		maskLanes = vi.totalBits / 32
		resVecTy = fmt.Sprintf("<%d x i32>", maskLanes)
		resVec = c.emitPMAddWD(vi.totalBits, aRaw, bRaw)
	case "pmaddubsw":
		maskLanes = vi.totalBits / 16
		resVecTy = fmt.Sprintf("<%d x i16>", maskLanes)
		nB := vi.totalBits / 8
		bTy := fmt.Sprintf("<%d x i8>", nB)
		wTy := fmt.Sprintf("<%d x i16>", nB)
		az, bs, mul, ev, od, sum := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", az, bTy, aRaw, wTy)
		fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", bs, bTy, bRaw, wTy)
		fmt.Fprintf(c.b, "  %%%s = mul %s %%%s, %%%s\n", mul, wTy, az, bs)
		evM, odM := x86EvenOddMasks(nB)
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <%d x i32> <%s>\n", ev, wTy, mul, wTy, maskLanes, evM)
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <%d x i32> <%s>\n", od, wTy, mul, wTy, maskLanes, odM)
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.sadd.sat.v%di16(%s %%%s, %s %%%s)\n", sum, resVecTy, maskLanes, resVecTy, ev, resVecTy, od)
		resVec = "%" + sum
	case "pmulhrsw":
		maskLanes = vi.totalBits / 16
		resVecTy = fmt.Sprintf("<%d x i16>", maskLanes)
		w32Ty := fmt.Sprintf("<%d x i32>", maskLanes)
		ab, bb, as, bs, mul, sh1, add1, sh2, tr := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", ab, vi.byteVecTy, aRaw, resVecTy)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bb, vi.byteVecTy, bRaw, resVecTy)
		fmt.Fprintf(c.b, "  %%%s = sext %s %%%s to %s\n", as, resVecTy, ab, w32Ty)
		fmt.Fprintf(c.b, "  %%%s = sext %s %%%s to %s\n", bs, resVecTy, bb, w32Ty)
		fmt.Fprintf(c.b, "  %%%s = mul %s %%%s, %%%s\n", mul, w32Ty, as, bs)
		fmt.Fprintf(c.b, "  %%%s = ashr %s %%%s, %s\n", sh1, w32Ty, mul, x86IntSplat(maskLanes, 32, 14))
		fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %s\n", add1, w32Ty, sh1, x86IntSplat(maskLanes, 32, 1))
		fmt.Fprintf(c.b, "  %%%s = ashr %s %%%s, %s\n", sh2, w32Ty, add1, x86IntSplat(maskLanes, 32, 1))
		fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", tr, w32Ty, sh2, resVecTy)
		resVec = "%" + tr
	case "pmadd52":
		maskLanes = vi.totalBits / 64
		resVecTy = fmt.Sprintf("<%d x i64>", maskLanes)
		w128Ty := fmt.Sprintf("<%d x i128>", maskLanes)
		oldB, err := vi.loadReg(dstOp.Reg)
		if err != nil {
			return err
		}
		ab, bb, db := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", ab, vi.byteVecTy, aRaw, resVecTy)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bb, vi.byteVecTy, bRaw, resVecTy)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", db, vi.byteVecTy, oldB, resVecTy)
		m52 := x86IntSplat(maskLanes, 64, (int64(1)<<52)-1)
		am, bm, az, bz, mul := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %s\n", am, resVecTy, ab, m52)
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %s\n", bm, resVecTy, bb, m52)
		fmt.Fprintf(c.b, "  %%%s = zext %s %%%s to %s\n", az, resVecTy, am, w128Ty)
		fmt.Fprintf(c.b, "  %%%s = zext %s %%%s to %s\n", bz, resVecTy, bm, w128Ty)
		fmt.Fprintf(c.b, "  %%%s = mul %s %%%s, %%%s\n", mul, w128Ty, az, bz)
		prod128 := "%" + mul
		if spec.SubOp == 1 {
			sh := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %s\n", sh, w128Ty, prod128, x86IntSplat(maskLanes, 128, 52))
			prod128 = "%" + sh
		}
		tr, m2, add := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc %s %s to %s\n", tr, w128Ty, prod128, resVecTy)
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %s\n", m2, resVecTy, tr, m52)
		fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", add, resVecTy, db, m2)
		resVec = "%" + add
	case "vpdp":
		maskLanes = vi.totalBits / 32
		resVecTy = fmt.Sprintf("<%d x i32>", maskLanes)
		oldB, err := vi.loadReg(dstOp.Reg)
		if err != nil {
			return err
		}
		db := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", db, vi.byteVecTy, oldB, resVecTy)
		var dot string
		if spec.LaneBits == 16 {
			dot = c.emitPMAddWD(vi.totalBits, aRaw, bRaw)
		} else {
			// VPDPBUSD[S]: 4 uint8 * int8 pairs summed into each i32
			nB := vi.totalBits / 8
			bTy := fmt.Sprintf("<%d x i8>", nB)
			dTy := fmt.Sprintf("<%d x i32>", nB)
			az, bs, mul := c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", az, bTy, aRaw, dTy)
			fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", bs, bTy, bRaw, dTy)
			fmt.Fprintf(c.b, "  %%%s = mul %s %%%s, %%%s\n", mul, dTy, az, bs)
			parts := make([]string, 4)
			for k := 0; k < 4; k++ {
				ms := make([]string, maskLanes)
				for i := 0; i < maskLanes; i++ {
					ms[i] = fmt.Sprintf("i32 %d", i*4+k)
				}
				sh := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <%d x i32> <%s>\n", sh, dTy, mul, dTy, maskLanes, strings.Join(ms, ", "))
				parts[k] = "%" + sh
			}
			s01, s23, sAll := c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", s01, resVecTy, parts[0], parts[1])
			fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", s23, resVecTy, parts[2], parts[3])
			fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", sAll, resVecTy, s01, s23)
			dot = "%" + sAll
		}
		acc := c.newTmp()
		if spec.Saturating {
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.sadd.sat.v%di32(%s %%%s, %s %s)\n", acc, resVecTy, maskLanes, resVecTy, db, resVecTy, dot)
		} else {
			fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %s\n", acc, resVecTy, db, dot)
		}
		resVec = "%" + acc
	}
	if hasMask {
		oldB, err := vi.loadReg(dstOp.Reg)
		if err != nil {
			return err
		}
		oldBC := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", oldBC, vi.byteVecTy, oldB, resVecTy)
		resVec, err = c.x86ApplyMask(kreg, zeroMask, maskLanes, resVecTy, resVec, "%"+oldBC)
		if err != nil {
			return err
		}
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, resVecTy, resVec, vi.byteVecTy)
	return vi.storeVec(dstOp.Reg, "%"+out)
}

func (c *amd64Ctx) emitPMAddWD(totalBits int, aBytes, bBytes string) string {
	nW := totalBits / 16
	nD := totalBits / 32
	bTy := fmt.Sprintf("<%d x i8>", totalBits/8)
	wTy := fmt.Sprintf("<%d x i16>", nW)
	w32Ty := fmt.Sprintf("<%d x i32>", nW)
	dTy := fmt.Sprintf("<%d x i32>", nD)
	ab, bb, as, bs, mul, ev, od, sum := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", ab, bTy, aBytes, wTy)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bb, bTy, bBytes, wTy)
	fmt.Fprintf(c.b, "  %%%s = sext %s %%%s to %s\n", as, wTy, ab, w32Ty)
	fmt.Fprintf(c.b, "  %%%s = sext %s %%%s to %s\n", bs, wTy, bb, w32Ty)
	fmt.Fprintf(c.b, "  %%%s = mul %s %%%s, %%%s\n", mul, w32Ty, as, bs)
	evM, odM := x86EvenOddMasks(nW)
	fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <%d x i32> <%s>\n", ev, w32Ty, mul, w32Ty, nD, evM)
	fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <%d x i32> <%s>\n", od, w32Ty, mul, w32Ty, nD, odM)
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", sum, dTy, ev, od)
	return "%" + sum
}

func x86EvenOddMasks(n int) (string, string) {
	half := n / 2
	ev := make([]string, half)
	od := make([]string, half)
	for i := 0; i < half; i++ {
		ev[i] = fmt.Sprintf("i32 %d", 2*i)
		od[i] = fmt.Sprintf("i32 %d", 2*i+1)
	}
	return strings.Join(ev, ", "), strings.Join(od, ", ")
}

func (c *amd64Ctx) lowerX86FunnelRot(spec asm.OpSpec, zeroMask, bcst bool, ins asm.Instr) error {
	args, kreg, hasMask := x86StripEVEXMask(ins.Args)
	laneBits := int(spec.LaneBits)
	intrBase := "@llvm.fshl"
	if spec.SubOp == 1 {
		intrBase = "@llvm.fshr"
	}

	if spec.LLVMOp == "funnel_imm" {
		if len(args) != 4 || args[0].Kind != asm.OpImm || args[3].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects $imm, src2, src1, [K,] dst: %q", spec.Op, ins.Raw)
		}
		vi, ok := c.x86VecInfoForReg(args[3].Reg)
		if !ok {
			return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
		}
		lanes := vi.totalBits / laneBits
		vecTy := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
		s2, err := c.x86LoadVecOrBcst(vi, args[1], bcst, laneBits)
		if err != nil {
			return err
		}
		s1, err := vi.loadVec(args[2])
		if err != nil {
			return err
		}
		b1, b2, res := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", b1, vi.byteVecTy, s1, vecTy)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", b2, vi.byteVecTy, s2, vecTy)
		amt := x86IntSplat(lanes, laneBits, args[0].Imm&int64(laneBits-1))
		hi, lo := "%"+b1, "%"+b2
		if spec.SubOp == 1 {
			hi, lo = "%"+b2, "%"+b1
		}
		fmt.Fprintf(c.b, "  %%%s = call %s %s.v%di%d(%s %s, %s %s, %s %s)\n", res, vecTy, intrBase, lanes, laneBits, vecTy, hi, vecTy, lo, vecTy, amt)
		outV := "%" + res
		if hasMask {
			oldB, err := vi.loadReg(args[3].Reg)
			if err != nil {
				return err
			}
			ob := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", ob, vi.byteVecTy, oldB, vecTy)
			outV, err = c.x86ApplyMask(kreg, zeroMask, lanes, vecTy, outV, "%"+ob)
			if err != nil {
				return err
			}
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, vecTy, outV, vi.byteVecTy)
		return vi.storeVec(args[3].Reg, "%"+out)
	}

	// funnel_var (VPSHLDV*/VPSHRDV*) or vrot_var (VPROLV*/VPRORV*)
	if len(args) != 3 || args[2].Kind != asm.OpReg {
		return fmt.Errorf("amd64 %s expects src2, src1, [K,] dst: %q", spec.Op, ins.Raw)
	}
	vi, ok := c.x86VecInfoForReg(args[2].Reg)
	if !ok {
		return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
	}
	lanes := vi.totalBits / laneBits
	vecTy := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
	s0, err := c.x86LoadVecOrBcst(vi, args[0], bcst, laneBits)
	if err != nil {
		return err
	}
	s1, err := vi.loadVec(args[1])
	if err != nil {
		return err
	}
	oldB, err := vi.loadReg(args[2].Reg)
	if err != nil {
		return err
	}
	b0, b1, bOld, res := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", b0, vi.byteVecTy, s0, vecTy)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", b1, vi.byteVecTy, s1, vecTy)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bOld, vi.byteVecTy, oldB, vecTy)
	if spec.LLVMOp == "vrot_var" {
		// VPROLV/VPRORV shiftCnt, src, [K,] dst
		fmt.Fprintf(c.b, "  %%%s = call %s %s.v%di%d(%s %%%s, %s %%%s, %s %%%s)\n", res, vecTy, intrBase, lanes, laneBits, vecTy, b1, vecTy, b1, vecTy, b0)
	} else {
		// VPSHLDV/VPSHRDV shiftCnt, src2, [K,] dst (dst is src1!)
		hi, lo := "%"+bOld, "%"+b1
		if spec.SubOp == 1 {
			hi, lo = "%"+b1, "%"+bOld
		}
		fmt.Fprintf(c.b, "  %%%s = call %s %s.v%di%d(%s %s, %s %s, %s %%%s)\n", res, vecTy, intrBase, lanes, laneBits, vecTy, hi, vecTy, lo, vecTy, b0)
	}
	outV := "%" + res
	if hasMask {
		outV, err = c.x86ApplyMask(kreg, zeroMask, lanes, vecTy, outV, "%"+bOld)
		if err != nil {
			return err
		}
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, vecTy, outV, vi.byteVecTy)
	return vi.storeVec(args[2].Reg, "%"+out)
}

func (c *amd64Ctx) lowerX86SADMultiShift(spec asm.OpSpec, zeroMask, bcst bool, ins asm.Instr) error {
	args, kreg, hasMask := x86StripEVEXMask(ins.Args)
	if spec.LLVMOp == "multishiftqb" {
		if len(args) != 3 || args[2].Kind != asm.OpReg {
			return fmt.Errorf("amd64 VPMULTISHIFTQB expects src, ctrl, [K,] dst: %q", ins.Raw)
		}
		vi, ok := c.x86VecInfoForReg(args[2].Reg)
		if !ok {
			return fmt.Errorf("amd64 VPMULTISHIFTQB dst must be vector reg: %q", ins.Raw)
		}
		srcB, err := c.x86LoadVecOrBcst(vi, args[0], bcst, 64)
		if err != nil {
			return err
		}
		ctrlB, err := vi.loadVec(args[1])
		if err != nil {
			return err
		}
		nQ := vi.totalBits / 64
		nB := vi.totalBits / 8
		qTy := fmt.Sprintf("<%d x i64>", nQ)
		sq := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", sq, vi.byteVecTy, srcB, qTy)
		acc := "zeroinitializer"
		for bi := 0; bi < nB; bi++ {
			qi := bi / 8
			qVal, cByte, cSh, sh64, ror, tr, insE := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 %d\n", qVal, qTy, sq, qi)
			fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", cByte, vi.byteVecTy, ctrlB, bi)
			fmt.Fprintf(c.b, "  %%%s = and i8 %%%s, 63\n", cSh, cByte)
			fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i64\n", sh64, cSh)
			fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.fshr.i64(i64 %%%s, i64 %%%s, i64 %%%s)\n", ror, qVal, qVal, sh64)
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i8\n", tr, ror)
			fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, i8 %%%s, i32 %d\n", insE, vi.byteVecTy, acc, tr, bi)
			acc = "%" + insE
		}
		if hasMask {
			oldB, err := vi.loadReg(args[2].Reg)
			if err != nil {
				return err
			}
			acc, err = c.x86ApplyMask(kreg, zeroMask, nB, vi.byteVecTy, acc, oldB)
			if err != nil {
				return err
			}
		}
		return vi.storeVec(args[2].Reg, acc)
	}

	// MPSADBW / VMPSADBW / VDBPSADBW
	var imm int64
	var srcOp, lhsOp, dstOp asm.Operand
	if spec.ThreeOp {
		if len(args) != 4 || args[0].Kind != asm.OpImm || args[3].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects $imm, src, lhs, [K,] dst: %q", spec.Op, ins.Raw)
		}
		imm, srcOp, lhsOp, dstOp = args[0].Imm, args[1], args[2], args[3]
	} else {
		if len(args) != 3 || args[0].Kind != asm.OpImm || args[2].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects $imm, src, dst: %q", spec.Op, ins.Raw)
		}
		imm, srcOp, lhsOp, dstOp = args[0].Imm, args[1], args[2], args[2]
	}
	vi, ok := c.x86VecInfoForReg(dstOp.Reg)
	if !ok {
		return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
	}
	srcB, err := vi.loadVec(srcOp)
	if err != nil {
		return err
	}
	lhsB, err := vi.loadVec(lhsOp)
	if err != nil {
		return err
	}
	nW := vi.totalBits / 16
	wTy := fmt.Sprintf("<%d x i16>", nW)
	acc := "zeroinitializer"
	nBlocks := vi.totalBits / 128
	for blk := 0; blk < nBlocks; blk++ {
		baseB := blk * 16
		baseW := blk * 8
		if spec.LLVMOp == "dbpsadbw" {
			// VDBPSADBW: shuffle dwords of srcB per imm, then compute 8 4-byte SADs per 128-bit lane
			for j := 0; j < 8; j++ {
				sum := "0"
				aBase := baseB + (j/2)*4 + (j%2)*4
				if aBase+3 >= baseB+16 {
					aBase = baseB + 12
				}
				bSel := int((imm >> uint((j%4)*2)) & 3)
				bBase := baseB + bSel*4
				for k := 0; k < 4; k++ {
					ai := baseB + ((aBase - baseB + k) % 16)
					bi := baseB + ((bBase - baseB + k) % 16)
					ea, eb, za, zb, df, ab, ad := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", ea, vi.byteVecTy, lhsB, ai)
					fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", eb, vi.byteVecTy, srcB, bi)
					fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i16\n", za, ea)
					fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i16\n", zb, eb)
					fmt.Fprintf(c.b, "  %%%s = sub i16 %%%s, %%%s\n", df, za, zb)
					fmt.Fprintf(c.b, "  %%%s = call i16 @llvm.abs.i16(i16 %%%s, i1 false)\n", ab, df)
					fmt.Fprintf(c.b, "  %%%s = add i16 %s, %%%s\n", ad, sum, ab)
					sum = "%" + ad
				}
				insW := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, i16 %s, i32 %d\n", insW, wTy, acc, sum, baseW+j)
				acc = "%" + insW
			}
		} else {
			blkShift := uint((blk % 2) * 3)
			srcOff := int((imm>>blkShift)&3) * 4
			lhsOff := int((imm>>(blkShift+2))&1) * 4
			for j := 0; j < 8; j++ {
				sum := "0"
				for k := 0; k < 4; k++ {
					ea, eb, za, zb, df, ab, ad := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", ea, vi.byteVecTy, lhsB, baseB+lhsOff+j+k)
					fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", eb, vi.byteVecTy, srcB, baseB+srcOff+k)
					fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i16\n", za, ea)
					fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i16\n", zb, eb)
					fmt.Fprintf(c.b, "  %%%s = sub i16 %%%s, %%%s\n", df, za, zb)
					fmt.Fprintf(c.b, "  %%%s = call i16 @llvm.abs.i16(i16 %%%s, i1 false)\n", ab, df)
					fmt.Fprintf(c.b, "  %%%s = add i16 %s, %%%s\n", ad, sum, ab)
					sum = "%" + ad
				}
				insW := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, i16 %s, i32 %d\n", insW, wTy, acc, sum, baseW+j)
				acc = "%" + insW
			}
		}
	}
	if hasMask {
		oldB, err := vi.loadReg(dstOp.Reg)
		if err != nil {
			return err
		}
		ob := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", ob, vi.byteVecTy, oldB, wTy)
		acc, err = c.x86ApplyMask(kreg, zeroMask, nW, wTy, acc, "%"+ob)
		if err != nil {
			return err
		}
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, wTy, acc, vi.byteVecTy)
	return vi.storeVec(dstOp.Reg, "%"+out)
}

func x86FCmpPred(imm int64) string {
	preds := [32]string{
		"oeq", "olt", "ole", "uno", "une", "uge", "ugt", "ord",
		"ueq", "ult", "ule", "false", "one", "oge", "ogt", "true",
		"oeq", "olt", "ole", "uno", "une", "uge", "ugt", "ord",
		"ueq", "ult", "ule", "false", "one", "oge", "ogt", "true",
	}
	return preds[imm&31]
}

func (c *amd64Ctx) lowerX86VCMPFP(spec asm.OpSpec, bcst bool, ins asm.Instr) error {
	args, kreg, hasMask := x86StripEVEXMask(ins.Args)
	if len(args) != 4 || args[0].Kind != asm.OpImm || args[3].Kind != asm.OpReg {
		return fmt.Errorf("amd64 %s expects $imm, src2, src1, [K,] dst: %q", spec.Op, ins.Raw)
	}
	pred := x86FCmpPred(args[0].Imm)
	laneBits := int(spec.LaneBits)
	isScalar := spec.SubOp == 1
	kDst := isAMD64KReg(args[3].Reg)

	if isScalar {
		fpTy := "double"
		if laneBits == 32 {
			fpTy = "float"
		}
		var a, b string
		var err error
		if laneBits == 32 {
			b, err = c.evalF32(args[1])
			if err == nil {
				a, err = c.evalF32(args[2])
			}
		} else {
			b, err = c.evalF64(args[1])
			if err == nil {
				a, err = c.evalF64(args[2])
			}
		}
		if err != nil {
			return err
		}
		cmp := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fcmp %s %s %s, %s\n", cmp, pred, fpTy, a, b)
		if kDst {
			z := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i1 %%%s to i64\n", z, cmp)
			kv := "%" + z
			if hasMask {
				km, err := c.loadK(kreg)
				if err != nil {
					return err
				}
				and := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = and i64 %s, %s\n", and, kv, km)
				kv = "%" + and
			}
			return c.storeK(args[3].Reg, kv)
		}
		// VEX scalar vector dst: low lane all-1s/0, upper lanes from src1
		x1, err := c.loadXVecOperand(args[2])
		if err != nil {
			return err
		}
		intTy := fmt.Sprintf("i%d", laneBits)
		nL := 128 / laneBits
		vTy := fmt.Sprintf("<%d x %s>", nL, intTy)
		sx, bc, ins0, out := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sext i1 %%%s to %s\n", sx, cmp, intTy)
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", bc, x1, vTy)
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %%%s, %s %%%s, i32 0\n", ins0, vTy, bc, intTy, sx)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", out, vTy, ins0)
		return c.storeX(args[3].Reg, "%"+out)
	}

	// Packed VCMPPS / VCMPPD
	var vi x86VecInfo
	var ok bool
	if kDst {
		if args[2].Kind == asm.OpReg {
			vi, ok = c.x86VecInfoForReg(args[2].Reg)
		}
		if !ok && args[1].Kind == asm.OpReg {
			vi, ok = c.x86VecInfoForReg(args[1].Reg)
		}
	} else {
		vi, ok = c.x86VecInfoForReg(args[3].Reg)
	}
	if !ok {
		return fmt.Errorf("amd64 %s requires vector register operand: %q", spec.Op, ins.Raw)
	}
	lanes := vi.totalBits / laneBits
	fpElem := "double"
	if laneBits == 32 {
		fpElem = "float"
	}
	fpVecTy := fmt.Sprintf("<%d x %s>", lanes, fpElem)
	bRaw, err := c.x86LoadVecOrBcst(vi, args[1], bcst, laneBits)
	if err != nil {
		return err
	}
	aRaw, err := vi.loadVec(args[2])
	if err != nil {
		return err
	}
	ab, bb, cmp := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", ab, vi.byteVecTy, aRaw, fpVecTy)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bb, vi.byteVecTy, bRaw, fpVecTy)
	fmt.Fprintf(c.b, "  %%%s = fcmp %s %s %%%s, %%%s\n", cmp, pred, fpVecTy, ab, bb)
	if kDst {
		kv := c.x86PackI1VecToK("%"+cmp, lanes)
		if hasMask {
			km, err := c.loadK(kreg)
			if err != nil {
				return err
			}
			and := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i64 %s, %s\n", and, kv, km)
			kv = "%" + and
		}
		return c.storeK(args[3].Reg, kv)
	}
	intVecTy := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
	sx, out := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sext <%d x i1> %%%s to %s\n", sx, lanes, cmp, intVecTy)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to %s\n", out, intVecTy, sx, vi.byteVecTy)
	return vi.storeVec(args[3].Reg, "%"+out)
}

func (c *amd64Ctx) lowerX86VPTESTM(spec asm.OpSpec, bcst bool, ins asm.Instr) error {
	args, kreg, hasMask := x86StripEVEXMask(ins.Args)
	if len(args) != 3 || args[2].Kind != asm.OpReg || !isAMD64KReg(args[2].Reg) {
		return fmt.Errorf("amd64 %s expects src2, src1, [K,] Kdst: %q", spec.Op, ins.Raw)
	}
	var vi x86VecInfo
	var ok bool
	if args[1].Kind == asm.OpReg {
		vi, ok = c.x86VecInfoForReg(args[1].Reg)
	}
	if !ok && args[0].Kind == asm.OpReg {
		vi, ok = c.x86VecInfoForReg(args[0].Reg)
	}
	if !ok {
		return fmt.Errorf("amd64 %s requires vector source register: %q", spec.Op, ins.Raw)
	}
	laneBits := int(spec.LaneBits)
	lanes := vi.totalBits / laneBits
	vecTy := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
	bRaw, err := c.x86LoadVecOrBcst(vi, args[0], bcst, laneBits)
	if err != nil {
		return err
	}
	aRaw, err := vi.loadVec(args[1])
	if err != nil {
		return err
	}
	ab, bb, andv, cmp := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", ab, vi.byteVecTy, aRaw, vecTy)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bb, vi.byteVecTy, bRaw, vecTy)
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %%%s\n", andv, vecTy, ab, bb)
	cond := "ne"
	if spec.SubOp == 1 {
		cond = "eq"
	}
	fmt.Fprintf(c.b, "  %%%s = icmp %s %s %%%s, zeroinitializer\n", cmp, cond, vecTy, andv)
	kv := c.x86PackI1VecToK("%"+cmp, lanes)
	if hasMask {
		km, err := c.loadK(kreg)
		if err != nil {
			return err
		}
		and := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, %s\n", and, kv, km)
		kv = "%" + and
	}
	return c.storeK(args[2].Reg, kv)
}

func (c *amd64Ctx) lowerX86PTEST(spec asm.OpSpec, ins asm.Instr) error {
	if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
		return fmt.Errorf("amd64 %s expects src, dstReg: %q", spec.Op, ins.Raw)
	}
	vi, ok := c.x86VecInfoForReg(ins.Args[1].Reg)
	if !ok {
		return fmt.Errorf("amd64 %s requires vector register: %q", spec.Op, ins.Raw)
	}
	srcB, err := vi.loadVec(ins.Args[0])
	if err != nil {
		return err
	}
	dstB, err := vi.loadReg(ins.Args[1].Reg)
	if err != nil {
		return err
	}
	if spec.LLVMOp == "vtestfp" {
		// VTESTPS/VTESTPD test sign bits of each float/double lane.
		laneBits := int(spec.LaneBits)
		lanes := vi.totalBits / laneBits
		vecTy := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
		signMask := x86IntSplat(lanes, laneBits, int64(1)<<uint(laneBits-1))
		sb, db, sm, dm, and1, notd, and2 := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", sb, vi.byteVecTy, srcB, vecTy)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", db, vi.byteVecTy, dstB, vecTy)
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %s\n", sm, vecTy, sb, signMask)
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %s\n", dm, vecTy, db, signMask)
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %%%s\n", and1, vecTy, dm, sm)
		fmt.Fprintf(c.b, "  %%%s = xor %s %%%s, %s\n", notd, vecTy, dm, signMask)
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %%%s\n", and2, vecTy, notd, sm)
		intTy := fmt.Sprintf("i%d", vi.totalBits)
		i1, i2, zf, cf := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to %s\n", i1, vecTy, and1, intTy)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to %s\n", i2, vecTy, and2, intTy)
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, 0\n", zf, intTy, i1)
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, 0\n", cf, intTy, i2)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zf, c.flagsZSlot)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
		return nil
	}
	intTy := fmt.Sprintf("i%d", vi.totalBits)
	si, di, and1, notd, and2, zf, cf := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", si, vi.byteVecTy, srcB, intTy)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", di, vi.byteVecTy, dstB, intTy)
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %%%s\n", and1, intTy, di, si)
	fmt.Fprintf(c.b, "  %%%s = xor %s %%%s, -1\n", notd, intTy, di)
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %%%s\n", and2, intTy, notd, si)
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, 0\n", zf, intTy, and1)
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, 0\n", cf, intTy, and2)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zf, c.flagsZSlot)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
	return nil
}

func (c *amd64Ctx) lowerX86GatherScatter(spec asm.OpSpec, ins asm.Instr) error {
	if len(ins.Args) != 3 {
		return fmt.Errorf("amd64 %s expects 3 operands: %q", spec.Op, ins.Raw)
	}
	idxBits := int(spec.SrcWidth)
	dataBits := int(spec.Width)
	dataKind := cvtKindSInt
	if spec.Float {
		dataKind = cvtKindFP
	}
	dataElemTy := x86CVTElemType(dataKind, dataBits)

	if spec.LLVMOp == "scatter" {
		// VPSCATTER*/VSCATTER* Vsrc, Kmask, disp(base)(Vidx*scale)
		if ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg || !isAMD64KReg(ins.Args[1].Reg) || ins.Args[2].Kind != asm.OpMem {
			return fmt.Errorf("amd64 %s expects Vsrc, Kmask, vsibMem: %q", spec.Op, ins.Raw)
		}
		svi, ok := c.x86VecInfoForReg(ins.Args[0].Reg)
		if !ok {
			return fmt.Errorf("amd64 %s invalid src reg: %q", spec.Op, ins.Raw)
		}
		mem := ins.Args[2].Mem
		ivi, ok := c.x86VecInfoForReg(mem.Index)
		if !ok {
			return fmt.Errorf("amd64 %s requires vector index in VSIB: %q", spec.Op, ins.Raw)
		}
		lanes := minInt(svi.totalBits/dataBits, ivi.totalBits/idxBits)
		ptrs, err := c.emitVSIBPtrs(mem, ivi, idxBits, lanes)
		if err != nil {
			return err
		}
		mvec, err := c.x86KToI1Vec(ins.Args[1].Reg, lanes)
		if err != nil {
			return err
		}
		srcVal, err := c.x86LoadTypedLanes(ins.Args[0], lanes, dataBits, dataElemTy, false)
		if err != nil {
			return err
		}
		vecTy := fmt.Sprintf("<%d x %s>", lanes, dataElemTy)
		mangle := x86LLVMVecMangle(lanes, dataKind, dataBits)
		fmt.Fprintf(c.b, "  call void @llvm.masked.scatter.%s.v%dp0(%s %s, <%d x ptr> %s, i32 1, <%d x i1> %s)\n",
			mangle, lanes, vecTy, srcVal, lanes, ptrs, lanes, mvec)
		return c.storeK(ins.Args[1].Reg, "0")
	}

	// Gather:
	//   AVX-512: VGATHER* vsibMem, Kmask, Vdst
	//   AVX2:    VGATHER* Vmask, vsibMem, Vdst
	if ins.Args[2].Kind != asm.OpReg {
		return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
	}
	dvi, ok := c.x86VecInfoForReg(ins.Args[2].Reg)
	if !ok {
		return fmt.Errorf("amd64 %s invalid dst reg: %q", spec.Op, ins.Raw)
	}
	isAVX512 := ins.Args[0].Kind == asm.OpMem && ins.Args[1].Kind == asm.OpReg && isAMD64KReg(ins.Args[1].Reg)
	var mem asm.MemRef
	if isAVX512 {
		mem = ins.Args[0].Mem
	} else {
		if ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpMem {
			return fmt.Errorf("amd64 %s expects (vsibMem, Kmask, Vdst) or (Vmask, vsibMem, Vdst): %q", spec.Op, ins.Raw)
		}
		mem = ins.Args[1].Mem
	}
	ivi, ok := c.x86VecInfoForReg(mem.Index)
	if !ok {
		return fmt.Errorf("amd64 %s requires vector index in VSIB: %q", spec.Op, ins.Raw)
	}
	dstFullLanes := dvi.totalBits / dataBits
	lanes := minInt(dstFullLanes, ivi.totalBits/idxBits)
	ptrs, err := c.emitVSIBPtrs(mem, ivi, idxBits, lanes)
	if err != nil {
		return err
	}
	var mvec string
	if isAVX512 {
		mvec, err = c.x86KToI1Vec(ins.Args[1].Reg, lanes)
		if err != nil {
			return err
		}
	} else {
		mvi, ok := c.x86VecInfoForReg(ins.Args[0].Reg)
		if !ok {
			return fmt.Errorf("amd64 %s invalid Vmask reg: %q", spec.Op, ins.Raw)
		}
		mRaw, err := mvi.loadReg(ins.Args[0].Reg)
		if err != nil {
			return err
		}
		mFull := mvi.totalBits / dataBits
		mFullTy := fmt.Sprintf("<%d x i%d>", mFull, dataBits)
		mb := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", mb, mvi.byteVecTy, mRaw, mFullTy)
		mVal := "%" + mb
		mTy := mFullTy
		if mFull != lanes {
			sh := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s zeroinitializer, <%d x i32> %s\n",
				sh, mFullTy, mb, mFullTy, lanes, llvmI32RangeMask(0, lanes))
			mVal = "%" + sh
			mTy = fmt.Sprintf("<%d x i%d>", lanes, dataBits)
		}
		cmp := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, zeroinitializer\n", cmp, mTy, mVal)
		mvec = "%" + cmp
	}
	passthru, err := c.x86LoadTypedLanes(ins.Args[2], lanes, dataBits, dataElemTy, false)
	if err != nil {
		return err
	}
	vecTy := fmt.Sprintf("<%d x %s>", lanes, dataElemTy)
	mangle := x86LLVMVecMangle(lanes, dataKind, dataBits)
	g := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.masked.gather.%s.v%dp0(<%d x ptr> %s, i32 1, <%d x i1> %s, %s %s)\n",
		g, vecTy, mangle, lanes, lanes, ptrs, lanes, mvec, vecTy, passthru)
	res := "%" + g
	dstFullTy := fmt.Sprintf("<%d x %s>", dstFullLanes, dataElemTy)
	if lanes < dstFullLanes {
		pad := c.newTmp()
		me := make([]string, dstFullLanes)
		for i := 0; i < dstFullLanes; i++ {
			if i < lanes {
				me[i] = fmt.Sprintf("i32 %d", i)
			} else {
				me[i] = fmt.Sprintf("i32 %d", lanes)
			}
		}
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s zeroinitializer, <%d x i32> <%s>\n",
			pad, vecTy, res, vecTy, dstFullLanes, strings.Join(me, ", "))
		res = "%" + pad
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, dstFullTy, res, dvi.byteVecTy)
	if err := dvi.storeVec(ins.Args[2].Reg, "%"+out); err != nil {
		return err
	}
	// Clear mask register per x86 gather architectural contract.
	if isAVX512 {
		return c.storeK(ins.Args[1].Reg, "0")
	}
	mvi, _ := c.x86VecInfoForReg(ins.Args[0].Reg)
	return mvi.storeVec(ins.Args[0].Reg, "zeroinitializer")
}

func (c *amd64Ctx) emitVSIBPtrs(mem asm.MemRef, ivi x86VecInfo, idxBits, lanes int) (string, error) {
	baseVal := "0"
	if mem.Base != "" {
		bv, err := c.loadReg(mem.Base)
		if err != nil {
			return "", err
		}
		baseVal = bv
	} else if mem.Sym != "" {
		p, err := c.ptrFromSB(mem.Sym)
		if err != nil {
			return "", err
		}
		pi := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", pi, p)
		baseVal = "%" + pi
	}
	if mem.Off != 0 {
		ad := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", ad, baseVal, mem.Off)
		baseVal = "%" + ad
	}
	idxRaw, err := ivi.loadReg(mem.Index)
	if err != nil {
		return "", err
	}
	idxFull := ivi.totalBits / idxBits
	idxFullTy := fmt.Sprintf("<%d x i%d>", idxFull, idxBits)
	ib := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", ib, ivi.byteVecTy, idxRaw, idxFullTy)
	iv := "%" + ib
	idxTy := fmt.Sprintf("<%d x i%d>", lanes, idxBits)
	if idxFull != lanes {
		sh := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s zeroinitializer, <%d x i32> %s\n",
			sh, idxFullTy, ib, idxFullTy, lanes, llvmI32RangeMask(0, lanes))
		iv = "%" + sh
	}
	qTy := fmt.Sprintf("<%d x i64>", lanes)
	i64v := iv
	if idxBits == 32 {
		sx := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", sx, idxTy, iv, qTy)
		i64v = "%" + sx
	}
	scale := mem.Scale
	if scale == 0 {
		scale = 1
	}
	if scale > 1 {
		sc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = mul %s %s, %s\n", sc, qTy, i64v, x86IntSplat(lanes, 64, int64(scale)))
		i64v = "%" + sc
	}
	b0, bSplat, addr, ptrs := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement %s undef, i64 %s, i32 0\n", b0, qTy, baseVal)
	fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <%d x i32> zeroinitializer\n", bSplat, qTy, b0, qTy, lanes)
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %s\n", addr, qTy, bSplat, i64v)
	fmt.Fprintf(c.b, "  %%%s = inttoptr %s %%%s to <%d x ptr>\n", ptrs, qTy, addr, lanes)
	return "%" + ptrs, nil
}

func (c *amd64Ctx) lowerX86VPLZCNT(spec asm.OpSpec, zeroMask, bcst bool, ins asm.Instr) error {
	args, kreg, hasMask := x86StripEVEXMask(ins.Args)
	if len(args) != 2 || args[1].Kind != asm.OpReg {
		return fmt.Errorf("amd64 %s expects src, [K,] dst: %q", spec.Op, ins.Raw)
	}
	vi, ok := c.x86VecInfoForReg(args[1].Reg)
	if !ok {
		return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
	}
	laneBits := int(spec.LaneBits)
	lanes := vi.totalBits / laneBits
	vecTy := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
	raw, err := c.x86LoadVecOrBcst(vi, args[0], bcst, laneBits)
	if err != nil {
		return err
	}
	bc, lz := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bc, vi.byteVecTy, raw, vecTy)
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.ctlz.v%di%d(%s %%%s, i1 false)\n", lz, vecTy, lanes, laneBits, vecTy, bc)
	res := "%" + lz
	if hasMask {
		oldB, err := vi.loadReg(args[1].Reg)
		if err != nil {
			return err
		}
		ob := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", ob, vi.byteVecTy, oldB, vecTy)
		res, err = c.x86ApplyMask(kreg, zeroMask, lanes, vecTy, res, "%"+ob)
		if err != nil {
			return err
		}
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, vecTy, res, vi.byteVecTy)
	return vi.storeVec(args[1].Reg, "%"+out)
}

func (c *amd64Ctx) lowerX86VPerm(spec asm.OpSpec, zeroMask, bcst bool, ins asm.Instr) error {
	args, kreg, hasMask := x86StripEVEXMask(ins.Args)
	if len(args) != 3 || args[2].Kind != asm.OpReg {
		return fmt.Errorf("amd64 %s expects src1, src2, [K,] dst: %q", spec.Op, ins.Raw)
	}
	vi, ok := c.x86VecInfoForReg(args[2].Reg)
	if !ok {
		return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
	}
	laneBits := int(spec.LaneBits)
	lanes := vi.totalBits / laneBits
	intTy := fmt.Sprintf("i%d", laneBits)
	vecTy := fmt.Sprintf("<%d x %s>", lanes, intTy)

	raw0, err := c.x86LoadVecOrBcst(vi, args[0], bcst, laneBits)
	if err != nil {
		return err
	}
	raw1, err := vi.loadVec(args[1])
	if err != nil {
		return err
	}
	oldB, err := vi.loadReg(args[2].Reg)
	if err != nil {
		return err
	}
	b0, b1, bOld := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", b0, vi.byteVecTy, raw0, vecTy)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", b1, vi.byteVecTy, raw1, vecTy)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bOld, vi.byteVecTy, oldB, vecTy)

	if spec.LLVMOp == "vperm1" {
		// VPERMD/VPERMPS/VPERMW srcTable, idxVec, [K,] dst
		idxMask := lanes - 1
		acc := "zeroinitializer"
		for i := 0; i < lanes; i++ {
			ix, m, ex, insE := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 %d\n", ix, vecTy, b1, i)
			fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %d\n", m, intTy, ix, idxMask)
			fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, %s %%%s\n", ex, vecTy, b0, intTy, m)
			fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, %s %%%s, i32 %d\n", insE, vecTy, acc, intTy, ex, i)
			acc = "%" + insE
		}
		if hasMask {
			acc, err = c.x86ApplyMask(kreg, zeroMask, lanes, vecTy, acc, "%"+bOld)
			if err != nil {
				return err
			}
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, vecTy, acc, vi.byteVecTy)
		return vi.storeVec(args[2].Reg, "%"+out)
	}

	// vperm2: VPERMI2* (SubOp=0: dst=idx, src2=t1, src1=t2) or VPERMT2* (SubOp=1: src2=idx, dst=t1, src1=t2)
	var idxVec, t1Vec, t2Vec string
	if spec.SubOp == 0 {
		idxVec, t1Vec, t2Vec = "%"+bOld, "%"+b1, "%"+b0
	} else {
		idxVec, t1Vec, t2Vec = "%"+b1, "%"+bOld, "%"+b0
	}
	// Concatenate t1 and t2 into a <2*lanes x iN> table so extractelement is 1 IR op per lane!
	dblTy := fmt.Sprintf("<%d x %s>", 2*lanes, intTy)
	cat := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s %s, <%d x i32> %s\n",
		cat, vecTy, t1Vec, vecTy, t2Vec, 2*lanes, llvmI32RangeMask(0, 2*lanes))
	idxMask := 2*lanes - 1
	acc := "zeroinitializer"
	for i := 0; i < lanes; i++ {
		ix, m, ex, insE := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", ix, vecTy, idxVec, i)
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %d\n", m, intTy, ix, idxMask)
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, %s %%%s\n", ex, dblTy, cat, intTy, m)
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, %s %%%s, i32 %d\n", insE, vecTy, acc, intTy, ex, i)
		acc = "%" + insE
	}
	if hasMask {
		acc, err = c.x86ApplyMask(kreg, zeroMask, lanes, vecTy, acc, "%"+bOld)
		if err != nil {
			return err
		}
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, vecTy, acc, vi.byteVecTy)
	return vi.storeVec(args[2].Reg, "%"+out)
}

func (c *amd64Ctx) lowerX86VExpand(spec asm.OpSpec, zeroMask bool, ins asm.Instr) error {
	args, kreg, hasMask := x86StripEVEXMask(ins.Args)
	if len(args) != 2 || args[1].Kind != asm.OpReg {
		return fmt.Errorf("amd64 %s expects src, [K,] dst: %q", spec.Op, ins.Raw)
	}
	vi, ok := c.x86VecInfoForReg(args[1].Reg)
	if !ok {
		return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
	}
	laneBits := int(spec.LaneBits)
	lanes := vi.totalBits / laneBits
	intTy := fmt.Sprintf("i%d", laneBits)
	vecTy := fmt.Sprintf("<%d x %s>", lanes, intTy)
	if !hasMask {
		raw, err := vi.loadVec(args[0])
		if err != nil {
			return err
		}
		return vi.storeVec(args[1].Reg, raw)
	}
	kv, err := c.loadK(kreg)
	if err != nil {
		return err
	}
	oldB, err := vi.loadReg(args[1].Reg)
	if err != nil {
		return err
	}
	ob := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", ob, vi.byteVecTy, oldB, vecTy)
	var srcVec string
	if args[0].Kind == asm.OpReg {
		sr, err := vi.loadReg(args[0].Reg)
		if err != nil {
			return err
		}
		sb := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", sb, vi.byteVecTy, sr, vecTy)
		srcVec = "%" + sb
	} else {
		// Load contiguous source elements into a vector (for mem, use masked.load or plain load).
		sr, err := vi.loadVec(args[0])
		if err != nil {
			return err
		}
		sb := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", sb, vi.byteVecTy, sr, vecTy)
		srcVec = "%" + sb
	}
	// Expand: active bit i reads srcVec[popcount(k & ((1<<i)-1))].
	acc := "zeroinitializer"
	if !zeroMask {
		acc = "%" + ob
	}
	pos := "0"
	for i := 0; i < lanes; i++ {
		sh, bit, el, cur, sel, insE, inc, nextPos := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, %d\n", sh, kv, i)
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i1\n", bit, sh)
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %s\n", el, vecTy, srcVec, pos)
		if zeroMask {
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %%%s, %s 0\n", sel, bit, intTy, el, intTy)
			_ = cur
		} else {
			fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 %d\n", cur, vecTy, ob, i)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %%%s, %s %%%s\n", sel, bit, intTy, el, intTy, cur)
		}
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, %s %%%s, i32 %d\n", insE, vecTy, acc, intTy, sel, i)
		acc = "%" + insE
		fmt.Fprintf(c.b, "  %%%s = zext i1 %%%s to i32\n", inc, bit)
		fmt.Fprintf(c.b, "  %%%s = add i32 %s, %%%s\n", nextPos, pos, inc)
		pos = "%" + nextPos
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, vecTy, acc, vi.byteVecTy)
	return vi.storeVec(args[1].Reg, "%"+out)
}

func (c *amd64Ctx) lowerX86VPConflict(spec asm.OpSpec, zeroMask, bcst bool, ins asm.Instr) error {
	args, kreg, hasMask := x86StripEVEXMask(ins.Args)
	if len(args) != 2 || args[1].Kind != asm.OpReg {
		return fmt.Errorf("amd64 %s expects src, [K,] dst: %q", spec.Op, ins.Raw)
	}
	vi, ok := c.x86VecInfoForReg(args[1].Reg)
	if !ok {
		return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
	}
	laneBits := int(spec.LaneBits)
	lanes := vi.totalBits / laneBits
	intTy := fmt.Sprintf("i%d", laneBits)
	vecTy := fmt.Sprintf("<%d x %s>", lanes, intTy)
	raw, err := c.x86LoadVecOrBcst(vi, args[0], bcst, laneBits)
	if err != nil {
		return err
	}
	sb := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", sb, vi.byteVecTy, raw, vecTy)
	elems := make([]string, lanes)
	for i := 0; i < lanes; i++ {
		e := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 %d\n", e, vecTy, sb, i)
		elems[i] = "%" + e
	}
	acc := "zeroinitializer"
	for i := 1; i < lanes; i++ {
		mask := "0"
		for j := 0; j < i; j++ {
			eq, bit, orv := c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, %s\n", eq, intTy, elems[i], elems[j])
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %d, %s 0\n", bit, eq, intTy, int64(1)<<uint(j), intTy)
			fmt.Fprintf(c.b, "  %%%s = or %s %s, %%%s\n", orv, intTy, mask, bit)
			mask = "%" + orv
		}
		insE := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, %s %s, i32 %d\n", insE, vecTy, acc, intTy, mask, i)
		acc = "%" + insE
	}
	if hasMask {
		oldB, err := vi.loadReg(args[1].Reg)
		if err != nil {
			return err
		}
		ob := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", ob, vi.byteVecTy, oldB, vecTy)
		acc, err = c.x86ApplyMask(kreg, zeroMask, lanes, vecTy, acc, "%"+ob)
		if err != nil {
			return err
		}
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, vecTy, acc, vi.byteVecTy)
	return vi.storeVec(args[1].Reg, "%"+out)
}

func (c *amd64Ctx) lowerX86VBcastSub(spec asm.OpSpec, zeroMask bool, ins asm.Instr) error {
	args, kreg, hasMask := x86StripEVEXMask(ins.Args)
	if len(args) != 2 || args[1].Kind != asm.OpReg {
		return fmt.Errorf("amd64 %s expects src, [K,] dst: %q", spec.Op, ins.Raw)
	}
	dvi, ok := c.x86VecInfoForReg(args[1].Reg)
	if !ok {
		return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
	}
	subBytes := int(spec.Width) / 8
	dstBytes := dvi.totalBits / 8
	subTy := fmt.Sprintf("<%d x i8>", subBytes)
	subVal, err := c.x86LoadTypedLanes(args[0], subBytes, 8, "i8", false)
	if err != nil {
		return err
	}
	me := make([]string, dstBytes)
	for i := 0; i < dstBytes; i++ {
		me[i] = fmt.Sprintf("i32 %d", i%subBytes)
	}
	sh := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s poison, <%d x i32> <%s>\n",
		sh, subTy, subVal, subTy, dstBytes, strings.Join(me, ", "))
	res := "%" + sh
	if hasMask {
		laneBits := int(spec.LaneBits)
		lanes := dvi.totalBits / laneBits
		vecTy := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
		oldB, err := dvi.loadReg(args[1].Reg)
		if err != nil {
			return err
		}
		rb, ob := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", rb, dvi.byteVecTy, res, vecTy)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", ob, dvi.byteVecTy, oldB, vecTy)
		mRes, err := c.x86ApplyMask(kreg, zeroMask, lanes, vecTy, "%"+rb, "%"+ob)
		if err != nil {
			return err
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, vecTy, mRes, dvi.byteVecTy)
		res = "%" + out
	}
	return dvi.storeVec(args[1].Reg, res)
}

func (c *amd64Ctx) lowerX86VPBcastM(spec asm.OpSpec, ins asm.Instr) error {
	if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpReg || !isAMD64KReg(ins.Args[0].Reg) || ins.Args[1].Kind != asm.OpReg {
		return fmt.Errorf("amd64 %s expects Ksrc, Vdst: %q", spec.Op, ins.Raw)
	}
	vi, ok := c.x86VecInfoForReg(ins.Args[1].Reg)
	if !ok {
		return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
	}
	kv, err := c.loadK(ins.Args[0].Reg)
	if err != nil {
		return err
	}
	laneBits := int(spec.LaneBits)
	lanes := vi.totalBits / laneBits
	elemTy := fmt.Sprintf("i%d", laneBits)
	vecTy := fmt.Sprintf("<%d x %s>", lanes, elemTy)
	mask := (int64(1) << uint(spec.SrcWidth)) - 1
	m, val := c.newTmp(), ""
	fmt.Fprintf(c.b, "  %%%s = and i64 %s, %d\n", m, kv, mask)
	if laneBits == 64 {
		val = "%" + m
	} else {
		tr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to %s\n", tr, m, elemTy)
		val = "%" + tr
	}
	ins0, splat, out := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement %s undef, %s %s, i32 0\n", ins0, vecTy, elemTy, val)
	fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <%d x i32> zeroinitializer\n", splat, vecTy, ins0, vecTy, lanes)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to %s\n", out, vecTy, splat, vi.byteVecTy)
	return vi.storeVec(ins.Args[1].Reg, "%"+out)
}

func (c *amd64Ctx) lowerX86KTestUnpck(spec asm.OpSpec, ins asm.Instr) error {
	if spec.LLVMOp == "kunpck" {
		if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg || ins.Args[2].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects Ksrc1, Ksrc2, Kdst: %q", spec.Op, ins.Raw)
		}
		k1, err := c.loadK(ins.Args[0].Reg)
		if err != nil {
			return err
		}
		k2, err := c.loadK(ins.Args[1].Reg)
		if err != nil {
			return err
		}
		w := int(spec.Width)
		mask := (uint64(1) << uint(w)) - 1
		lo, hi, sh, res := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, %d\n", lo, k1, mask)
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, %d\n", hi, k2, mask)
		fmt.Fprintf(c.b, "  %%%s = shl i64 %%%s, %d\n", sh, hi, w)
		fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %%%s\n", res, sh, lo)
		return c.storeK(ins.Args[2].Reg, "%"+res)
	}
	// KTEST / KORTEST
	if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg {
		return fmt.Errorf("amd64 %s expects K1, K2: %q", spec.Op, ins.Raw)
	}
	a64, err := c.loadK(ins.Args[0].Reg)
	if err != nil {
		return err
	}
	b64, err := c.loadK(ins.Args[1].Reg)
	if err != nil {
		return err
	}
	ty := x86LLVMIntType(spec.Width)
	a, b := a64, b64
	if ty != asm.I64 {
		ta, tb := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", ta, a64, ty)
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", tb, b64, ty)
		a, b = "%"+ta, "%"+tb
	}
	if spec.SubOp == 1 {
		// KORTEST: ZF = (a|b) == 0, CF = (a|b) == -1
		orv, zf, cf := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or %s %s, %s\n", orv, ty, a, b)
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, 0\n", zf, ty, orv)
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, -1\n", cf, ty, orv)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zf, c.flagsZSlot)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
		return nil
	}
	// KTEST: ZF = (b&a) == 0, CF = (~b&a) == 0
	and1, notb, and2, zf, cf := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", and1, ty, b, a)
	fmt.Fprintf(c.b, "  %%%s = xor %s %s, -1\n", notb, ty, b)
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %s\n", and2, ty, notb, a)
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, 0\n", zf, ty, and1)
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, 0\n", cf, ty, and2)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zf, c.flagsZSlot)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
	return nil
}

func (c *amd64Ctx) lowerX86VPShufBitQMB(ins asm.Instr) error {
	args, kreg, hasMask := x86StripEVEXMask(ins.Args)
	if len(args) != 3 || args[2].Kind != asm.OpReg || !isAMD64KReg(args[2].Reg) {
		return fmt.Errorf("amd64 VPSHUFBITQMB expects idx, src, [K,] Kdst: %q", ins.Raw)
	}
	var vi x86VecInfo
	var ok bool
	if args[1].Kind == asm.OpReg {
		vi, ok = c.x86VecInfoForReg(args[1].Reg)
	}
	if !ok && args[0].Kind == asm.OpReg {
		vi, ok = c.x86VecInfoForReg(args[0].Reg)
	}
	if !ok {
		return fmt.Errorf("amd64 VPSHUFBITQMB requires vector source reg: %q", ins.Raw)
	}
	idxB, err := vi.loadVec(args[0])
	if err != nil {
		return err
	}
	srcB, err := vi.loadVec(args[1])
	if err != nil {
		return err
	}
	nQ := vi.totalBits / 64
	nB := vi.totalBits / 8
	qTy := fmt.Sprintf("<%d x i64>", nQ)
	sq := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", sq, vi.byteVecTy, srcB, qTy)
	acc := "0"
	for bi := 0; bi < nB; bi++ {
		qi := bi / 8
		qv, ib, im, sh64, shr, bit1, bit64, shl, orv := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 %d\n", qv, qTy, sq, qi)
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", ib, vi.byteVecTy, idxB, bi)
		fmt.Fprintf(c.b, "  %%%s = and i8 %%%s, 63\n", im, ib)
		fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i64\n", sh64, im)
		fmt.Fprintf(c.b, "  %%%s = lshr i64 %%%s, %%%s\n", shr, qv, sh64)
		fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, 1\n", bit1, shr)
		fmt.Fprintf(c.b, "  %%%s = shl i64 %%%s, %d\n", shl, bit1, bi)
		_ = bit64
		fmt.Fprintf(c.b, "  %%%s = or i64 %s, %%%s\n", orv, acc, shl)
		acc = "%" + orv
	}
	if hasMask {
		km, err := c.loadK(kreg)
		if err != nil {
			return err
		}
		and := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, %s\n", and, acc, km)
		acc = "%" + and
	}
	return c.storeK(args[2].Reg, acc)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
