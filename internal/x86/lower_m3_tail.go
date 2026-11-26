package x86

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// M3 long-tail amd64 instruction specs and target-independent LLVM IR lowerers.
// Covers all 148 remaining non-x87 amd64 go-asm opcodes (431 forms) across:
//   1. AVX-512 FP math/rounding/range/class/fixup (54 ops)
//   2. SSE/AVX FP horizontal add/sub, addsub, round (20 ops)
//   3. Vector non-temporal, high/low, maskmov, MMX<->XMM moves (28 ops)
//   4. Scalar MOVBE, MOVNTI, BMI2 PDEP/PEXT, DIVQ/IDIV*, CWD, LAHF/SAHF,
//      PUSHW/POPW/PUSHFW/POPFW, XLAT, amd64 string ops, and system ops (46 ops).

var x86M3TailSpecs = []asm.OpSpec{
	// 1. AVX-512 FP Math / Rounding / Class / Fixup (54 ops; SubOp bit0 = scalar)
	{Op: "VRCP14PS", Family: asm.FamilyVecUnary, SubOp: 0, LaneBits: 32, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vrcp"},
	{Op: "VRCP14PD", Family: asm.FamilyVecUnary, SubOp: 0, LaneBits: 64, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vrcp"},
	{Op: "VRCP14SS", Family: asm.FamilyFP, SubOp: 1, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vrcp"},
	{Op: "VRCP14SD", Family: asm.FamilyFP, SubOp: 1, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vrcp"},
	{Op: "VRCP28PS", Family: asm.FamilyVecUnary, SubOp: 0, LaneBits: 32, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vrcp"},
	{Op: "VRCP28PD", Family: asm.FamilyVecUnary, SubOp: 0, LaneBits: 64, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vrcp"},
	{Op: "VRCP28SS", Family: asm.FamilyFP, SubOp: 1, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vrcp"},
	{Op: "VRCP28SD", Family: asm.FamilyFP, SubOp: 1, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vrcp"},
	{Op: "VRSQRT14PS", Family: asm.FamilyVecUnary, SubOp: 0, LaneBits: 32, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vrsqrt"},
	{Op: "VRSQRT14PD", Family: asm.FamilyVecUnary, SubOp: 0, LaneBits: 64, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vrsqrt"},
	{Op: "VRSQRT14SS", Family: asm.FamilyFP, SubOp: 1, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vrsqrt"},
	{Op: "VRSQRT14SD", Family: asm.FamilyFP, SubOp: 1, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vrsqrt"},
	{Op: "VRSQRT28PS", Family: asm.FamilyVecUnary, SubOp: 0, LaneBits: 32, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vrsqrt"},
	{Op: "VRSQRT28PD", Family: asm.FamilyVecUnary, SubOp: 0, LaneBits: 64, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vrsqrt"},
	{Op: "VRSQRT28SS", Family: asm.FamilyFP, SubOp: 1, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vrsqrt"},
	{Op: "VRSQRT28SD", Family: asm.FamilyFP, SubOp: 1, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vrsqrt"},
	{Op: "VEXP2PS", Family: asm.FamilyVecUnary, SubOp: 0, LaneBits: 32, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vexp2"},
	{Op: "VEXP2PD", Family: asm.FamilyVecUnary, SubOp: 0, LaneBits: 64, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vexp2"},
	{Op: "VGETEXPPS", Family: asm.FamilyVecUnary, SubOp: 0, LaneBits: 32, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vgetexp"},
	{Op: "VGETEXPPD", Family: asm.FamilyVecUnary, SubOp: 0, LaneBits: 64, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vgetexp"},
	{Op: "VGETEXPSS", Family: asm.FamilyFP, SubOp: 1, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vgetexp"},
	{Op: "VGETEXPSD", Family: asm.FamilyFP, SubOp: 1, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vgetexp"},
	{Op: "VGETMANTPS", Family: asm.FamilyVecUnary, SubOp: 0, LaneBits: 32, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vgetmant"},
	{Op: "VGETMANTPD", Family: asm.FamilyVecUnary, SubOp: 0, LaneBits: 64, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vgetmant"},
	{Op: "VGETMANTSS", Family: asm.FamilyFP, SubOp: 1, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vgetmant"},
	{Op: "VGETMANTSD", Family: asm.FamilyFP, SubOp: 1, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vgetmant"},
	{Op: "VRNDSCALEPS", Family: asm.FamilyVecUnary, SubOp: 0, LaneBits: 32, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vrndscale"},
	{Op: "VRNDSCALEPD", Family: asm.FamilyVecUnary, SubOp: 0, LaneBits: 64, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vrndscale"},
	{Op: "VRNDSCALESS", Family: asm.FamilyFP, SubOp: 1, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vrndscale"},
	{Op: "VRNDSCALESD", Family: asm.FamilyFP, SubOp: 1, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vrndscale"},
	{Op: "VREDUCEPS", Family: asm.FamilyVecUnary, SubOp: 0, LaneBits: 32, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vreduce"},
	{Op: "VREDUCEPD", Family: asm.FamilyVecUnary, SubOp: 0, LaneBits: 64, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vreduce"},
	{Op: "VREDUCESS", Family: asm.FamilyFP, SubOp: 1, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vreduce"},
	{Op: "VREDUCESD", Family: asm.FamilyFP, SubOp: 1, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vreduce"},
	{Op: "VSCALEFPS", Family: asm.FamilyVecFMA, SubOp: 0, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vscalef"},
	{Op: "VSCALEFPD", Family: asm.FamilyVecFMA, SubOp: 0, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vscalef"},
	{Op: "VSCALEFSS", Family: asm.FamilyFP, SubOp: 1, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vscalef"},
	{Op: "VSCALEFSD", Family: asm.FamilyFP, SubOp: 1, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vscalef"},
	{Op: "VRANGEPS", Family: asm.FamilyVecFMA, SubOp: 0, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vrange"},
	{Op: "VRANGEPD", Family: asm.FamilyVecFMA, SubOp: 0, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vrange"},
	{Op: "VRANGESS", Family: asm.FamilyFP, SubOp: 1, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vrange"},
	{Op: "VRANGESD", Family: asm.FamilyFP, SubOp: 1, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vrange"},
	{Op: "VFIXUPIMMPS", Family: asm.FamilyVecFMA, SubOp: 0, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "vfixupimm"},
	{Op: "VFIXUPIMMPD", Family: asm.FamilyVecFMA, SubOp: 0, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "vfixupimm"},
	{Op: "VFIXUPIMMSS", Family: asm.FamilyFP, SubOp: 1, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "vfixupimm"},
	{Op: "VFIXUPIMMSD", Family: asm.FamilyFP, SubOp: 1, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "vfixupimm"},
	{Op: "VFPCLASSPS", Family: asm.FamilyCompare, Width: 0, LaneBits: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "vfpclass"},
	{Op: "VFPCLASSPSX", Family: asm.FamilyCompare, Width: 128, LaneBits: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "vfpclass"},
	{Op: "VFPCLASSPSY", Family: asm.FamilyCompare, Width: 256, LaneBits: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "vfpclass"},
	{Op: "VFPCLASSPSZ", Family: asm.FamilyCompare, Width: 512, LaneBits: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "vfpclass"},
	{Op: "VFPCLASSPD", Family: asm.FamilyCompare, Width: 0, LaneBits: 64, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "vfpclass"},
	{Op: "VFPCLASSPDX", Family: asm.FamilyCompare, Width: 128, LaneBits: 64, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "vfpclass"},
	{Op: "VFPCLASSPDY", Family: asm.FamilyCompare, Width: 256, LaneBits: 64, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "vfpclass"},
	{Op: "VFPCLASSPDZ", Family: asm.FamilyCompare, Width: 512, LaneBits: 64, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "vfpclass"},
	{Op: "VFPCLASSSS", Family: asm.FamilyCompare, SubOp: 1, Width: 32, LaneBits: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "vfpclass"},
	{Op: "VFPCLASSSD", Family: asm.FamilyCompare, SubOp: 1, Width: 64, LaneBits: 64, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "vfpclass"},

	// 2. SSE/AVX FP Horizontal Add/Sub, AddSub, Round (20 ops)
	{Op: "ADDSUBPS", Family: asm.FamilyVecShuffle, LaneBits: 32, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "addsub"},
	{Op: "ADDSUBPD", Family: asm.FamilyVecShuffle, LaneBits: 64, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "addsub"},
	{Op: "VADDSUBPS", Family: asm.FamilyVecShuffle, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "addsub"},
	{Op: "VADDSUBPD", Family: asm.FamilyVecShuffle, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "addsub"},
	{Op: "HADDPS", Family: asm.FamilyVecShuffle, SubOp: 0, LaneBits: 32, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "fhaddsub"},
	{Op: "HADDPD", Family: asm.FamilyVecShuffle, SubOp: 0, LaneBits: 64, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "fhaddsub"},
	{Op: "VHADDPS", Family: asm.FamilyVecShuffle, SubOp: 0, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "fhaddsub"},
	{Op: "VHADDPD", Family: asm.FamilyVecShuffle, SubOp: 0, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "fhaddsub"},
	{Op: "HSUBPS", Family: asm.FamilyVecShuffle, SubOp: 1, LaneBits: 32, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "fhaddsub"},
	{Op: "HSUBPD", Family: asm.FamilyVecShuffle, SubOp: 1, LaneBits: 64, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "fhaddsub"},
	{Op: "VHSUBPS", Family: asm.FamilyVecShuffle, SubOp: 1, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "fhaddsub"},
	{Op: "VHSUBPD", Family: asm.FamilyVecShuffle, SubOp: 1, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "fhaddsub"},
	{Op: "ROUNDPS", Family: asm.FamilyVecUnary, SubOp: 0, LaneBits: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "round"},
	{Op: "ROUNDPD", Family: asm.FamilyVecUnary, SubOp: 0, LaneBits: 64, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "round"},
	{Op: "VROUNDPS", Family: asm.FamilyVecUnary, SubOp: 0, LaneBits: 32, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "round"},
	{Op: "VROUNDPD", Family: asm.FamilyVecUnary, SubOp: 0, LaneBits: 64, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "round"},
	{Op: "ROUNDSS", Family: asm.FamilyFP, SubOp: 1, LaneBits: 32, Float: true, Effect: asm.EffectPreserveUpper, LLVMOp: "round"},
	{Op: "ROUNDSD", Family: asm.FamilyFP, SubOp: 1, LaneBits: 64, Float: true, Effect: asm.EffectPreserveUpper, LLVMOp: "round"},
	{Op: "VROUNDSS", Family: asm.FamilyFP, SubOp: 1, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "round"},
	{Op: "VROUNDSD", Family: asm.FamilyFP, SubOp: 1, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "round"},

	// 3. Vector Non-Temporal / High-Low / MaskMov / MMX-XMM Moves (28 ops)
	{Op: "LDDQU", Family: asm.FamilyMove, Effect: asm.EffectWriteOnly, LLVMOp: "vmov_nt"},
	{Op: "VLDDQU", Family: asm.FamilyMove, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vmov_nt"},
	{Op: "MOVNTDQA", Family: asm.FamilyMove, Effect: asm.EffectWriteOnly, LLVMOp: "vmov_nt"},
	{Op: "VMOVNTDQA", Family: asm.FamilyMove, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vmov_nt"},
	{Op: "MOVNTDQ", Family: asm.FamilyMove, Effect: asm.EffectReadOnly, LLVMOp: "vmov_nt"},
	{Op: "MOVNTO", Family: asm.FamilyMove, Effect: asm.EffectReadOnly, LLVMOp: "vmov_nt"},
	{Op: "MOVNTPD", Family: asm.FamilyMove, Effect: asm.EffectReadOnly, LLVMOp: "vmov_nt"},
	{Op: "MOVNTPS", Family: asm.FamilyMove, Effect: asm.EffectReadOnly, LLVMOp: "vmov_nt"},
	{Op: "MOVNTQ", Family: asm.FamilyMove, Effect: asm.EffectReadOnly, LLVMOp: "vmov_nt"},
	{Op: "VMOVNTPD", Family: asm.FamilyMove, Effect: asm.EffectReadOnly, LLVMOp: "vmov_nt"},
	{Op: "VMOVNTPS", Family: asm.FamilyMove, Effect: asm.EffectReadOnly, LLVMOp: "vmov_nt"},
	{Op: "MOVDQ2Q", Family: asm.FamilyMove, Effect: asm.EffectWriteOnly, LLVMOp: "movdq2q"},
	{Op: "MOVQOZX", Family: asm.FamilyMove, Effect: asm.EffectWriteOnly, LLVMOp: "movqozx"},
	{Op: "MOVHPD", Family: asm.FamilyMove, SubOp: 1, Effect: asm.EffectReadWrite, LLVMOp: "movhl"},
	{Op: "MOVHPS", Family: asm.FamilyMove, SubOp: 1, Effect: asm.EffectReadWrite, LLVMOp: "movhl"},
	{Op: "MOVLPD", Family: asm.FamilyMove, SubOp: 0, Effect: asm.EffectReadWrite, LLVMOp: "movhl"},
	{Op: "MOVLPS", Family: asm.FamilyMove, SubOp: 0, Effect: asm.EffectReadWrite, LLVMOp: "movhl"},
	{Op: "VMOVHPD", Family: asm.FamilyMove, SubOp: 1, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "movhl"},
	{Op: "VMOVHPS", Family: asm.FamilyMove, SubOp: 1, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "movhl"},
	{Op: "VMOVLPD", Family: asm.FamilyMove, SubOp: 0, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "movhl"},
	{Op: "VMOVLPS", Family: asm.FamilyMove, SubOp: 0, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "movhl"},
	{Op: "VMASKMOVPS", Family: asm.FamilyMove, LaneBits: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vmaskmov"},
	{Op: "VMASKMOVPD", Family: asm.FamilyMove, LaneBits: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vmaskmov"},
	{Op: "VPMASKMOVD", Family: asm.FamilyMove, LaneBits: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vmaskmov"},
	{Op: "VPMASKMOVQ", Family: asm.FamilyMove, LaneBits: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vmaskmov"},
	{Op: "MASKMOVQ", Family: asm.FamilyMove, Effect: asm.EffectReadOnly, LLVMOp: "maskmov_di"},
	{Op: "MASKMOVOU", Family: asm.FamilyMove, Effect: asm.EffectReadOnly, LLVMOp: "maskmov_di"},
	{Op: "VMASKMOVDQU", Family: asm.FamilyMove, Effect: asm.EffectReadOnly, LLVMOp: "maskmov_di"},

	// 4. Scalar MOVBE, MOVNTI, BMI2 PDEP/PEXT, DIV/IDIV, Stack, String, System (46 ops)
	{Op: "MOVBEW", Family: asm.FamilyMove, Width: 16, Effect: asm.EffectWriteOnly, LLVMOp: "movbe"},
	{Op: "MOVBEL", Family: asm.FamilyMove, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "movbe"},
	{Op: "MOVBEQ", Family: asm.FamilyMove, Width: 64, Effect: asm.EffectWriteOnly, LLVMOp: "movbe"},
	{Op: "MOVNTIL", Family: asm.FamilyMove, Width: 32, Effect: asm.EffectReadOnly, LLVMOp: "movnti"},
	{Op: "MOVNTIQ", Family: asm.FamilyMove, Width: 64, Effect: asm.EffectReadOnly, LLVMOp: "movnti"},
	{Op: "PDEPL", Family: asm.FamilyBit, SubOp: 0, Width: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "pdep_pext"},
	{Op: "PDEPQ", Family: asm.FamilyBit, SubOp: 0, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "pdep_pext"},
	{Op: "PEXTL", Family: asm.FamilyBit, SubOp: 1, Width: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "pdep_pext"},
	{Op: "PEXTQ", Family: asm.FamilyBit, SubOp: 1, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "pdep_pext"},
	{Op: "DIVQ", Family: asm.FamilyMulDiv, Width: 64, Effect: asm.EffectImplicit, Flags: asm.FlagsClobber, LLVMOp: "div_idiv"},
	{Op: "IDIVL", Family: asm.FamilyMulDiv, Width: 32, Signed: true, Effect: asm.EffectImplicit, Flags: asm.FlagsClobber, LLVMOp: "div_idiv"},
	{Op: "IDIVQ", Family: asm.FamilyMulDiv, Width: 64, Signed: true, Effect: asm.EffectImplicit, Flags: asm.FlagsClobber, LLVMOp: "div_idiv"},
	{Op: "CWD", Family: asm.FamilyALU, Width: 16, Effect: asm.EffectImplicit, LLVMOp: "cwd"},
	{Op: "LAHF", Family: asm.FamilySystem, Effect: asm.EffectImplicit, Flags: asm.FlagsRead, LLVMOp: "lahf"},
	{Op: "SAHF", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite, LLVMOp: "sahf"},
	{Op: "PUSHW", Family: asm.FamilyMove, Width: 16, Effect: asm.EffectImplicit, LLVMOp: "pushw"},
	{Op: "POPW", Family: asm.FamilyMove, Width: 16, Effect: asm.EffectImplicit, LLVMOp: "popw"},
	{Op: "PUSHFW", Family: asm.FamilySystem, Width: 16, Effect: asm.EffectImplicit, LLVMOp: "pushfw"},
	{Op: "POPFW", Family: asm.FamilySystem, Width: 16, Effect: asm.EffectImplicit, LLVMOp: "popfw"},
	{Op: "XLAT", Family: asm.FamilyMove, Width: 8, Effect: asm.EffectImplicit, LLVMOp: "xlat"},
	{Op: "CMPSB", Family: asm.FamilyString, Width: 8, Effect: asm.EffectImplicit, Flags: asm.FlagsWrite, LLVMOp: "cmps"},
	{Op: "CMPSW", Family: asm.FamilyString, Width: 16, Effect: asm.EffectImplicit, Flags: asm.FlagsWrite, LLVMOp: "cmps"},
	{Op: "CMPSL", Family: asm.FamilyString, Width: 32, Effect: asm.EffectImplicit, Flags: asm.FlagsWrite, LLVMOp: "cmps"},
	{Op: "CMPSQ", Family: asm.FamilyString, Width: 64, Effect: asm.EffectImplicit, Flags: asm.FlagsWrite, LLVMOp: "cmps"},
	{Op: "LODSB", Family: asm.FamilyString, Width: 8, Effect: asm.EffectImplicit, LLVMOp: "lods"},
	{Op: "LODSW", Family: asm.FamilyString, Width: 16, Effect: asm.EffectImplicit, LLVMOp: "lods"},
	{Op: "LODSL", Family: asm.FamilyString, Width: 32, Effect: asm.EffectImplicit, LLVMOp: "lods"},
	{Op: "LODSQ", Family: asm.FamilyString, Width: 64, Effect: asm.EffectImplicit, LLVMOp: "lods"},
	{Op: "SCASB", Family: asm.FamilyString, Width: 8, Effect: asm.EffectImplicit, Flags: asm.FlagsWrite, LLVMOp: "scas"},
	{Op: "SCASW", Family: asm.FamilyString, Width: 16, Effect: asm.EffectImplicit, Flags: asm.FlagsWrite, LLVMOp: "scas"},
	{Op: "SCASL", Family: asm.FamilyString, Width: 32, Effect: asm.EffectImplicit, Flags: asm.FlagsWrite, LLVMOp: "scas"},
	{Op: "SCASQ", Family: asm.FamilyString, Width: 64, Effect: asm.EffectImplicit, Flags: asm.FlagsWrite, LLVMOp: "scas"},
	{Op: "MOVSB", Family: asm.FamilyString, Width: 8, Effect: asm.EffectImplicit, LLVMOp: "movs"},
	{Op: "MOVSW", Family: asm.FamilyString, Width: 16, Effect: asm.EffectImplicit, LLVMOp: "movs"},
	{Op: "MOVSL", Family: asm.FamilyString, Width: 32, Effect: asm.EffectImplicit, LLVMOp: "movs"},
	{Op: "MOVSQ", Family: asm.FamilyString, Width: 64, Effect: asm.EffectImplicit, LLVMOp: "movs"},
	{Op: "STOSB", Family: asm.FamilyString, Width: 8, Effect: asm.EffectImplicit, LLVMOp: "stos"},
	{Op: "STOSW", Family: asm.FamilyString, Width: 16, Effect: asm.EffectImplicit, LLVMOp: "stos"},
	{Op: "STOSL", Family: asm.FamilyString, Width: 32, Effect: asm.EffectImplicit, LLVMOp: "stos"},
	{Op: "STOSQ", Family: asm.FamilyString, Width: 64, Effect: asm.EffectImplicit, LLVMOp: "stos"},
	{Op: "LGDT", Family: asm.FamilySystem, SubOp: 0, Effect: asm.EffectReadOnly, LLVMOp: "sys_mem"},
	{Op: "LIDT", Family: asm.FamilySystem, SubOp: 0, Effect: asm.EffectReadOnly, LLVMOp: "sys_mem"},
	{Op: "SGDT", Family: asm.FamilySystem, SubOp: 1, Effect: asm.EffectWriteOnly, LLVMOp: "sys_mem"},
	{Op: "SIDT", Family: asm.FamilySystem, SubOp: 1, Effect: asm.EffectWriteOnly, LLVMOp: "sys_mem"},
	{Op: "LLDT", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "sys_rm"},
	{Op: "LMSW", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "sys_rm"},
	{Op: "LTR", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "sys_rm"},
	{Op: "TPAUSE", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "sys_rm"},
	{Op: "UMWAIT", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "sys_rm"},
}

var x86M3TailTable = asm.NewOpTable(x86M3TailSpecs)

func (c *amd64Ctx) lowerM3Tail(op asm.Op, ins asm.Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(ins.Op))
	zeroMask := strings.Contains(rawOp, ".Z")
	bcst := strings.Contains(rawOp, ".BCST")
	baseOp := op
	if dot := strings.IndexByte(string(baseOp), '.'); dot >= 0 {
		baseOp = asm.Op(string(baseOp)[:dot])
	}
	spec, found := x86M3TailTable.Lookup(baseOp)
	if !found {
		return false, false, nil
	}
	switch spec.LLVMOp {
	case "vrcp", "vrsqrt", "vexp2", "vgetexp", "vgetmant", "vrndscale", "vreduce", "round":
		return true, false, c.lowerX86M3FPUnary(spec, zeroMask, bcst, ins)
	case "vscalef", "vrange", "vfixupimm":
		return true, false, c.lowerX86M3FPBinary(spec, zeroMask, bcst, ins)
	case "vfpclass":
		return true, false, c.lowerX86VFPClass(spec, bcst, ins)
	case "addsub", "fhaddsub":
		return true, false, c.lowerX86FPAddSubHoriz(spec, ins)
	case "vmov_nt", "movdq2q", "movqozx", "movhl", "vmaskmov", "maskmov_di":
		return true, false, c.lowerX86M3VecMove(spec, ins)
	case "movbe", "movnti", "pdep_pext", "div_idiv", "cwd", "lahf", "sahf", "pushw", "popw", "pushfw", "popfw", "xlat":
		return true, false, c.lowerX86M3Scalar(spec, ins)
	case "cmps", "lods", "scas", "movs", "stos":
		return true, false, c.lowerX86M3String(spec, ins)
	case "sys_mem", "sys_rm":
		return true, false, c.lowerX86M3Sys(spec, ins)
	}
	return false, false, nil
}

func x86RoundIntrinsic(imm int64) string {
	switch imm & 3 {
	case 1:
		return "floor"
	case 2:
		return "ceil"
	case 3:
		return "trunc"
	default:
		return "rint"
	}
}

func (c *amd64Ctx) emitX86FPUnaryCore(opName string, imm int64, lanes, laneBits int, fpTy, mangle, x string) string {
	one := "1.0"
	if lanes > 1 {
		elems := make([]string, lanes)
		elem := "double 1.0"
		if laneBits == 32 {
			elem = "float 1.0"
		}
		for i := range elems {
			elems[i] = elem
		}
		one = "<" + strings.Join(elems, ", ") + ">"
	}
	switch opName {
	case "vrcp":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fdiv %s %s, %s\n", t, fpTy, one, x)
		return "%" + t
	case "vrsqrt":
		sq, d := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.sqrt.%s(%s %s)\n", sq, fpTy, mangle, fpTy, x)
		fmt.Fprintf(c.b, "  %%%s = fdiv %s %s, %%%s\n", d, fpTy, one, sq)
		return "%" + d
	case "vexp2":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.exp2.%s(%s %s)\n", t, fpTy, mangle, fpTy, x)
		return "%" + t
	case "round", "vrndscale":
		fn := x86RoundIntrinsic(imm)
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.%s(%s %s)\n", t, fpTy, fn, mangle, fpTy, x)
		return "%" + t
	case "vreduce":
		fn := x86RoundIntrinsic(imm)
		r, sub := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.%s(%s %s)\n", r, fpTy, fn, mangle, fpTy, x)
		fmt.Fprintf(c.b, "  %%%s = fsub %s %s, %%%s\n", sub, fpTy, x, r)
		return "%" + sub
	case "vgetexp":
		// Extract unbiased IEEE-754 exponent as floating-point value.
		intTy := fmt.Sprintf("i%d", laneBits)
		if lanes > 1 {
			intTy = fmt.Sprintf("<%d x i%d>", lanes, laneBits)
		}
		shiftAmt, maskVal, biasVal := int64(52), int64(0x7ff), int64(1023)
		if laneBits == 32 {
			shiftAmt, maskVal, biasVal = 23, 0xff, 127
		}
		shiftOp := fmt.Sprintf("%d", shiftAmt)
		maskOp := fmt.Sprintf("%d", maskVal)
		biasOp := fmt.Sprintf("%d", biasVal)
		if lanes > 1 {
			shiftOp = x86IntSplat(lanes, laneBits, shiftAmt)
			maskOp = x86IntSplat(lanes, laneBits, maskVal)
			biasOp = x86IntSplat(lanes, laneBits, biasVal)
		}
		bi, sh, an, sub, fp := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bi, fpTy, x, intTy)
		fmt.Fprintf(c.b, "  %%%s = lshr %s %%%s, %s\n", sh, intTy, bi, shiftOp)
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %s\n", an, intTy, sh, maskOp)
		fmt.Fprintf(c.b, "  %%%s = sub %s %%%s, %s\n", sub, intTy, an, biasOp)
		fmt.Fprintf(c.b, "  %%%s = sitofp %s %%%s to %s\n", fp, intTy, sub, fpTy)
		return "%" + fp
	default: // vgetmant
		intTy := fmt.Sprintf("i%d", laneBits)
		if lanes > 1 {
			intTy = fmt.Sprintf("<%d x i%d>", lanes, laneBits)
		}
		mantMask, expOne := int64(0x000fffffffffffff), int64(0x3ff0000000000000)
		if laneBits == 32 {
			mantMask, expOne = 0x007fffff, 0x3f800000
		}
		mmOp, eoOp := fmt.Sprintf("%d", mantMask), fmt.Sprintf("%d", expOne)
		if lanes > 1 {
			mmOp = x86IntSplat(lanes, laneBits, mantMask)
			eoOp = x86IntSplat(lanes, laneBits, expOne)
		}
		bi, an, orv, fp := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bi, fpTy, x, intTy)
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %s\n", an, intTy, bi, mmOp)
		fmt.Fprintf(c.b, "  %%%s = or %s %%%s, %s\n", orv, intTy, an, eoOp)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to %s\n", fp, intTy, orv, fpTy)
		return "%" + fp
	}
}

func (c *amd64Ctx) lowerX86M3FPUnary(spec asm.OpSpec, zeroMask, bcst bool, ins asm.Instr) error {
	args, kreg, hasMask := x86StripEVEXMask(ins.Args)
	hasImm := spec.LLVMOp == "vgetmant" || spec.LLVMOp == "vrndscale" || spec.LLVMOp == "vreduce" || spec.LLVMOp == "round"
	var imm int64
	if hasImm {
		if len(args) < 3 || args[0].Kind != asm.OpImm {
			return fmt.Errorf("amd64 %s expects $imm, ...: %q", spec.Op, ins.Raw)
		}
		imm = args[0].Imm
		args = args[1:]
	}
	laneBits := int(spec.LaneBits)
	isScalar := spec.SubOp == 1
	if isScalar {
		// Scalar: either 2-op (ROUNDSS/ROUNDSD: src, Xdst) or 3-op (V*: src, Xupper, [K,] Xdst)
		var srcOp, upperOp, dstOp asm.Operand
		if spec.ThreeOp {
			if len(args) != 3 || args[2].Kind != asm.OpReg || !isAMD64XReg(args[2].Reg) {
				return fmt.Errorf("amd64 %s expects src, Xsrc2, [K,] Xdst: %q", spec.Op, ins.Raw)
			}
			srcOp, upperOp, dstOp = args[0], args[1], args[2]
		} else {
			if len(args) != 2 || args[1].Kind != asm.OpReg || !isAMD64XReg(args[1].Reg) {
				return fmt.Errorf("amd64 %s expects src, Xdst: %q", spec.Op, ins.Raw)
			}
			srcOp, upperOp, dstOp = args[0], args[1], args[1]
		}
		up, err := c.loadXVecOperand(upperOp)
		if err != nil {
			return err
		}
		if err := c.storeX(dstOp.Reg, up); err != nil {
			return err
		}
		fpTy, mangle := "double", "f64"
		if laneBits == 32 {
			fpTy, mangle = "float", "f32"
		}
		var xv, oldv string
		xv, err = c.x86EvalScalarFPMasked(srcOp, laneBits, kreg, hasMask)
		if err == nil {
			if laneBits == 32 {
				oldv, err = c.loadXLowF32(dstOp.Reg)
			} else {
				oldv, err = c.loadXLowF64(dstOp.Reg)
			}
		}
		if err != nil {
			return err
		}
		res := c.emitX86FPUnaryCore(spec.LLVMOp, imm, 1, laneBits, fpTy, mangle, xv)
		if hasMask {
			res, err = c.x86ApplyScalarMask(kreg, zeroMask, fpTy, res, oldv)
			if err != nil {
				return err
			}
		}
		if laneBits == 32 {
			return c.storeXLowF32(dstOp.Reg, res)
		}
		return c.storeXLowF64(dstOp.Reg, res)
	}

	// Packed unary: src, [K,] dst
	if len(args) != 2 || args[1].Kind != asm.OpReg {
		return fmt.Errorf("amd64 %s expects src, [K,] dst: %q", spec.Op, ins.Raw)
	}
	vi, ok := c.x86VecInfoForReg(args[1].Reg)
	if !ok {
		return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
	}
	lanes := vi.totalBits / laneBits
	elemTy, mangle := "double", fmt.Sprintf("v%df64", lanes)
	if laneBits == 32 {
		elemTy, mangle = "float", fmt.Sprintf("v%df32", lanes)
	}
	fpVecTy := fmt.Sprintf("<%d x %s>", lanes, elemTy)
	raw, err := c.x86LoadVecMasked(vi, args[0], bcst, laneBits, kreg, hasMask)
	if err != nil {
		return err
	}
	bc := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bc, vi.byteVecTy, raw, fpVecTy)
	res := c.emitX86FPUnaryCore(spec.LLVMOp, imm, lanes, laneBits, fpVecTy, mangle, "%"+bc)
	if hasMask {
		oldB, err := vi.loadReg(args[1].Reg)
		if err != nil {
			return err
		}
		ob := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", ob, vi.byteVecTy, oldB, fpVecTy)
		res, err = c.x86ApplyMask(kreg, zeroMask, lanes, fpVecTy, res, "%"+ob)
		if err != nil {
			return err
		}
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, fpVecTy, res, vi.byteVecTy)
	return vi.storeVec(args[1].Reg, "%"+out)
}

func (c *amd64Ctx) emitX86FPBinaryCore(opName string, imm int64, lanes int, fpTy, mangle, a, b, dstVal string) string {
	switch opName {
	case "vscalef":
		fl, ex, mul := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.floor.%s(%s %s)\n", fl, fpTy, mangle, fpTy, b)
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.exp2.%s(%s %%%s)\n", ex, fpTy, mangle, fpTy, fl)
		fmt.Fprintf(c.b, "  %%%s = fmul %s %s, %%%s\n", mul, fpTy, a, ex)
		return "%" + mul
	case "vrange":
		// imm[1:0]: 0=min, 1=max, 2=min_abs, 3=max_abs
		va, vb := a, b
		if (imm & 2) != 0 {
			fa, fb := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.fabs.%s(%s %s)\n", fa, fpTy, mangle, fpTy, a)
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.fabs.%s(%s %s)\n", fb, fpTy, mangle, fpTy, b)
			va, vb = "%"+fa, "%"+fb
		}
		pred := "olt"
		if (imm & 1) != 0 {
			pred = "ogt"
		}
		cmp, sel := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fcmp %s %s %s, %s\n", cmp, pred, fpTy, va, vb)
		condTy := "i1"
		if lanes > 1 {
			condTy = fmt.Sprintf("<%d x i1>", lanes)
		}
		fmt.Fprintf(c.b, "  %%%s = select %s %%%s, %s %s, %s %s\n", sel, condTy, cmp, fpTy, a, fpTy, b)
		return "%" + sel
	default: // vfixupimm: preserve normal finite source values (table-controlled special cases)
		isFin, sel := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fcmp ord %s %s, %s\n", isFin, fpTy, a, a)
		condTy := "i1"
		if lanes > 1 {
			condTy = fmt.Sprintf("<%d x i1>", lanes)
		}
		fmt.Fprintf(c.b, "  %%%s = select %s %%%s, %s %s, %s %s\n", sel, condTy, isFin, fpTy, a, fpTy, dstVal)
		return "%" + sel
	}
}

func (c *amd64Ctx) lowerX86M3FPBinary(spec asm.OpSpec, zeroMask, bcst bool, ins asm.Instr) error {
	args, kreg, hasMask := x86StripEVEXMask(ins.Args)
	hasImm := spec.LLVMOp == "vrange" || spec.LLVMOp == "vfixupimm"
	var imm int64
	if hasImm {
		if len(args) != 4 || args[0].Kind != asm.OpImm {
			return fmt.Errorf("amd64 %s expects $imm, src2, src1, [K,] dst: %q", spec.Op, ins.Raw)
		}
		imm = args[0].Imm
		args = args[1:]
	} else if len(args) != 3 {
		return fmt.Errorf("amd64 %s expects src2, src1, [K,] dst: %q", spec.Op, ins.Raw)
	}
	if args[2].Kind != asm.OpReg {
		return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
	}
	laneBits := int(spec.LaneBits)
	isScalar := spec.SubOp == 1
	if isScalar {
		if !isAMD64XReg(args[2].Reg) {
			return fmt.Errorf("amd64 %s expects X dst: %q", spec.Op, ins.Raw)
		}
		fpTy, mangle := "double", "f64"
		if laneBits == 32 {
			fpTy, mangle = "float", "f32"
		}
		var a, b, oldv string
		var err error
		b, err = c.x86EvalScalarFPMasked(args[0], laneBits, kreg, hasMask)
		if err == nil {
			a, err = c.x86EvalScalarFPMasked(args[1], laneBits, kreg, hasMask)
		}
		if err == nil {
			if laneBits == 32 {
				oldv, err = c.loadXLowF32(args[2].Reg)
			} else {
				oldv, err = c.loadXLowF64(args[2].Reg)
			}
		}
		if err != nil {
			return err
		}
		// Copy upper lanes from src1.
		up, err := c.loadXVecOperand(args[1])
		if err != nil {
			return err
		}
		if err := c.storeX(args[2].Reg, up); err != nil {
			return err
		}
		res := c.emitX86FPBinaryCore(spec.LLVMOp, imm, 1, fpTy, mangle, a, b, oldv)
		if hasMask {
			res, err = c.x86ApplyScalarMask(kreg, zeroMask, fpTy, res, oldv)
			if err != nil {
				return err
			}
		}
		if laneBits == 32 {
			return c.storeXLowF32(args[2].Reg, res)
		}
		return c.storeXLowF64(args[2].Reg, res)
	}

	vi, ok := c.x86VecInfoForReg(args[2].Reg)
	if !ok {
		return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
	}
	lanes := vi.totalBits / laneBits
	elemTy, mangle := "double", fmt.Sprintf("v%df64", lanes)
	if laneBits == 32 {
		elemTy, mangle = "float", fmt.Sprintf("v%df32", lanes)
	}
	fpVecTy := fmt.Sprintf("<%d x %s>", lanes, elemTy)
	bRaw, err := c.x86LoadVecMasked(vi, args[0], bcst, laneBits, kreg, hasMask)
	if err != nil {
		return err
	}
	aRaw, err := c.x86LoadVecMasked(vi, args[1], false, laneBits, kreg, hasMask)
	if err != nil {
		return err
	}
	oldB, err := vi.loadReg(args[2].Reg)
	if err != nil {
		return err
	}
	ab, bb, ob := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", ab, vi.byteVecTy, aRaw, fpVecTy)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bb, vi.byteVecTy, bRaw, fpVecTy)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", ob, vi.byteVecTy, oldB, fpVecTy)
	res := c.emitX86FPBinaryCore(spec.LLVMOp, imm, lanes, fpVecTy, mangle, "%"+ab, "%"+bb, "%"+ob)
	if hasMask {
		res, err = c.x86ApplyMask(kreg, zeroMask, lanes, fpVecTy, res, "%"+ob)
		if err != nil {
			return err
		}
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, fpVecTy, res, vi.byteVecTy)
	return vi.storeVec(args[2].Reg, "%"+out)
}

func (c *amd64Ctx) lowerX86VFPClass(spec asm.OpSpec, bcst bool, ins asm.Instr) error {
	args, kreg, hasMask := x86StripEVEXMask(ins.Args)
	if len(args) != 3 || args[0].Kind != asm.OpImm || args[2].Kind != asm.OpReg || !isAMD64KReg(args[2].Reg) {
		return fmt.Errorf("amd64 %s expects $imm, src, [K,] Kdst: %q", spec.Op, ins.Raw)
	}
	imm := args[0].Imm & 0xff
	laneBits := int(spec.LaneBits)
	isScalar := spec.SubOp == 1

	// Map x86 VFPCLASS imm8 bits to LLVM @llvm.is.fpclass mask (bit-exact mapping!):
	// x86 bit0=QNaN(0x002), bit1=+0(0x040), bit2=-0(0x020), bit3=+Inf(0x200),
	// bit4=-Inf(0x004), bit5=Denorm(0x090), bit6=NegFin(0x018), bit7=SNaN(0x001).
	llvmMask := 0
	if imm&0x01 != 0 {
		llvmMask |= 0x002
	}
	if imm&0x02 != 0 {
		llvmMask |= 0x040
	}
	if imm&0x04 != 0 {
		llvmMask |= 0x020
	}
	if imm&0x08 != 0 {
		llvmMask |= 0x200
	}
	if imm&0x10 != 0 {
		llvmMask |= 0x004
	}
	if imm&0x20 != 0 {
		llvmMask |= 0x090
	}
	if imm&0x40 != 0 {
		llvmMask |= 0x018
	}
	if imm&0x80 != 0 {
		llvmMask |= 0x001
	}

	if isScalar {
		fpTy, mangle := "double", "f64"
		if laneBits == 32 {
			fpTy, mangle = "float", "f32"
		}
		fv, err := c.x86EvalScalarFPMasked(args[1], laneBits, kreg, hasMask)
		if err != nil {
			return err
		}
		cl, z := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i1 @llvm.is.fpclass.%s(%s %s, i32 %d)\n", cl, mangle, fpTy, fv, llvmMask)
		fmt.Fprintf(c.b, "  %%%s = zext i1 %%%s to i64\n", z, cl)
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
		return c.storeK(args[2].Reg, kv)
	}

	totalBits := int(spec.Width)
	if totalBits == 0 {
		totalBits = 128
		if args[1].Kind == asm.OpReg {
			if vi, ok := c.x86VecInfoForReg(args[1].Reg); ok {
				totalBits = vi.totalBits
			}
		}
	}
	lanes := totalBits / laneBits
	elemTy, mangle := "double", fmt.Sprintf("v%df64", lanes)
	if laneBits == 32 {
		elemTy, mangle = "float", fmt.Sprintf("v%df32", lanes)
	}
	fpVecTy := fmt.Sprintf("<%d x %s>", lanes, elemTy)
	sv, err := c.x86LoadTypedLanesMasked(args[1], lanes, laneBits, elemTy, bcst, kreg, hasMask)
	if err != nil {
		return err
	}
	cl := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <%d x i1> @llvm.is.fpclass.%s(%s %s, i32 %d)\n", cl, lanes, mangle, fpVecTy, sv, llvmMask)
	kv := c.x86PackI1VecToK("%"+cl, lanes)
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

func (c *amd64Ctx) lowerX86FPAddSubHoriz(spec asm.OpSpec, ins asm.Instr) error {
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
	elemTy := "double"
	if laneBits == 32 {
		elemTy = "float"
	}
	vecTy := fmt.Sprintf("<%d x %s>", lanes, elemTy)
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

	if spec.LLVMOp == "addsub" {
		ad, sb, sel, out := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fadd %s %%%s, %%%s\n", ad, vecTy, ab, bb)
		fmt.Fprintf(c.b, "  %%%s = fsub %s %%%s, %%%s\n", sb, vecTy, ab, bb)
		mb := make([]string, lanes)
		for i := 0; i < lanes; i++ {
			if i%2 == 1 {
				mb[i] = "i1 true"
			} else {
				mb[i] = "i1 false"
			}
		}
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> <%s>, %s %%%s, %s %%%s\n", sel, lanes, strings.Join(mb, ", "), vecTy, ad, vecTy, sb)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to %s\n", out, vecTy, sel, vi.byteVecTy)
		return vi.storeVec(dstOp.Reg, "%"+out)
	}

	// HADDP*/HSUBP* per 128-bit lane
	chunkLanes := 128 / laneBits
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
	fop := "fadd"
	if spec.SubOp == 1 {
		fop = "fsub"
	}
	fmt.Fprintf(c.b, "  %%%s = %s %s %%%s, %%%s\n", res, fop, vecTy, ev, od)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to %s\n", out, vecTy, res, vi.byteVecTy)
	return vi.storeVec(dstOp.Reg, "%"+out)
}

func (c *amd64Ctx) lowerX86M3VecMove(spec asm.OpSpec, ins asm.Instr) error {
	switch spec.LLVMOp {
	case "vmov_nt":
		if len(ins.Args) != 2 {
			return fmt.Errorf("amd64 %s expects 2 operands: %q", spec.Op, ins.Raw)
		}
		if ins.Args[1].Kind == asm.OpReg {
			vi, ok := c.x86VecInfoForReg(ins.Args[1].Reg)
			if !ok {
				return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
			}
			v, err := vi.loadVec(ins.Args[0])
			if err != nil {
				return err
			}
			return vi.storeVec(ins.Args[1].Reg, v)
		}
		if ins.Args[0].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s store expects vector reg src: %q", spec.Op, ins.Raw)
		}
		vi, ok := c.x86VecInfoForReg(ins.Args[0].Reg)
		if !ok {
			return fmt.Errorf("amd64 %s src must be vector reg: %q", spec.Op, ins.Raw)
		}
		v, err := vi.loadReg(ins.Args[0].Reg)
		if err != nil {
			return err
		}
		var p, pty string
		switch ins.Args[1].Kind {
		case asm.OpMem:
			p, pty, err = c.ptrFromMem(ins.Args[1].Mem)
		case asm.OpSym:
			p, err = c.ptrFromSB(ins.Args[1].Sym)
			pty = "ptr"
		default:
			return fmt.Errorf("amd64 %s expects mem dst: %q", spec.Op, ins.Raw)
		}
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store %s %s, %s %s, align 1\n", vi.byteVecTy, v, pty, p)
		return nil

	case "movdq2q":
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg || !isAMD64MReg(ins.Args[1].Reg) {
			return fmt.Errorf("amd64 MOVDQ2Q expects Xsrc, Mdst: %q", ins.Raw)
		}
		x, err := c.loadX(ins.Args[0].Reg)
		if err != nil {
			return err
		}
		lo := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %s, <16 x i8> poison, <8 x i32> %s\n", lo, x, llvmI32RangeMask(0, 8))
		return c.storeM(ins.Args[1].Reg, "%"+lo)

	case "movqozx":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg || !isAMD64XReg(ins.Args[1].Reg) {
			return fmt.Errorf("amd64 MOVQOZX expects Msrc/Xsrc, Xdst: %q", ins.Raw)
		}
		if ins.Args[0].Kind == asm.OpReg && isAMD64XReg(ins.Args[0].Reg) {
			x, err := c.loadX(ins.Args[0].Reg)
			if err != nil {
				return err
			}
			pad := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %s, <16 x i8> zeroinitializer, <16 x i32> <i32 0, i32 1, i32 2, i32 3, i32 4, i32 5, i32 6, i32 7, i32 16, i32 17, i32 18, i32 19, i32 20, i32 21, i32 22, i32 23>\n", pad, x)
			return c.storeX(ins.Args[1].Reg, "%"+pad)
		}
		m, err := c.loadMVecOperand(ins.Args[0])
		if err != nil {
			return err
		}
		pad := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <8 x i8> %s, <8 x i8> zeroinitializer, <16 x i32> %s\n", pad, m, llvmI32RangeMask(0, 16))
		return c.storeX(ins.Args[1].Reg, "%"+pad)

	case "movhl":
		// MOV{H,L}P{S,D}: 2-op store (Xsrc, mem), 2-op SSE load (mem/Xsrc, Xdst), or 3-op VEX load (mem, Xsrc, Xdst)
		high := spec.SubOp == 1
		if len(ins.Args) == 2 && ins.Args[0].Kind == asm.OpReg && isAMD64XReg(ins.Args[0].Reg) && ins.Args[1].Kind == asm.OpReg && isAMD64XReg(ins.Args[1].Reg) {
			// Register-register HL move (MOVHLPS / MOVLHPS / MOVHPD X, X encoder form)
			sx, err := c.loadX(ins.Args[0].Reg)
			if err != nil {
				return err
			}
			dx, err := c.loadX(ins.Args[1].Reg)
			if err != nil {
				return err
			}
			sbc, dbc, el, insE, out := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			srcIdx, dstIdx := 0, 0
			if high {
				srcIdx, dstIdx = 0, 1
			}
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", sbc, sx)
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", dbc, dx)
			fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 %d\n", el, sbc, srcIdx)
			fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> %%%s, i64 %%%s, i32 %d\n", insE, dbc, el, dstIdx)
			fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", out, insE)
			return c.storeX(ins.Args[1].Reg, "%"+out)
		}
		if len(ins.Args) == 2 && ins.Args[0].Kind == asm.OpReg && isAMD64XReg(ins.Args[0].Reg) {
			x, err := c.loadX(ins.Args[0].Reg)
			if err != nil {
				return err
			}
			bc, el := c.newTmp(), c.newTmp()
			idx := 0
			if high {
				idx = 1
			}
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", bc, x)
			fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 %d\n", el, bc, idx)
			var p, pty string
			switch ins.Args[1].Kind {
			case asm.OpMem:
				p, pty, err = c.ptrFromMem(ins.Args[1].Mem)
			case asm.OpSym:
				p, err = c.ptrFromSB(ins.Args[1].Sym)
				pty = "ptr"
			default:
				return fmt.Errorf("amd64 %s store expects mem dst: %q", spec.Op, ins.Raw)
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(c.b, "  store i64 %%%s, %s %s, align 1\n", el, pty, p)
			return nil
		}
		var memOp, srcXOp, dstXOp asm.Operand
		if len(ins.Args) == 3 {
			memOp, srcXOp, dstXOp = ins.Args[0], ins.Args[1], ins.Args[2]
		} else if len(ins.Args) == 2 {
			memOp, srcXOp, dstXOp = ins.Args[0], ins.Args[1], ins.Args[1]
		} else {
			return fmt.Errorf("amd64 %s expects 2 or 3 operands: %q", spec.Op, ins.Raw)
		}
		if dstXOp.Kind != asm.OpReg || !isAMD64XReg(dstXOp.Reg) {
			return fmt.Errorf("amd64 %s load expects Xdst: %q", spec.Op, ins.Raw)
		}
		var p, pty string
		var err error
		switch memOp.Kind {
		case asm.OpMem:
			p, pty, err = c.ptrFromMem(memOp.Mem)
		case asm.OpSym:
			p, err = c.ptrFromSB(memOp.Sym)
			pty = "ptr"
		default:
			return fmt.Errorf("amd64 %s expects mem src: %q", spec.Op, ins.Raw)
		}
		if err != nil {
			return err
		}
		baseX, err := c.loadXVecOperand(srcXOp)
		if err != nil {
			return err
		}
		ld, bc, insE, out := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		idx := 0
		if high {
			idx = 1
		}
		fmt.Fprintf(c.b, "  %%%s = load i64, %s %s, align 1\n", ld, pty, p)
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", bc, baseX)
		fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> %%%s, i64 %%%s, i32 %d\n", insE, bc, ld, idx)
		fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", out, insE)
		return c.storeX(dstXOp.Reg, "%"+out)

	case "vmaskmov":
		// VMASKMOVP{S,D} / VPMASKMOV{D,Q}:
		//   load:  mem, Vmask, Vdst
		//   store: Vsrc, Vmask, mem
		if len(ins.Args) != 3 || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects (mem, Vmask, Vdst) or (Vsrc, Vmask, mem): %q", spec.Op, ins.Raw)
		}
		mvi, ok := c.x86VecInfoForReg(ins.Args[1].Reg)
		if !ok {
			return fmt.Errorf("amd64 %s invalid mask reg: %q", spec.Op, ins.Raw)
		}
		laneBits := int(spec.LaneBits)
		lanes := mvi.totalBits / laneBits
		vecTy := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
		mRaw, err := mvi.loadReg(ins.Args[1].Reg)
		if err != nil {
			return err
		}
		mb, mCond := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", mb, mvi.byteVecTy, mRaw, vecTy)
		fmt.Fprintf(c.b, "  %%%s = icmp slt %s %%%s, zeroinitializer\n", mCond, vecTy, mb)
		if ins.Args[2].Kind == asm.OpReg {
			// Load form
			dvi, ok := c.x86VecInfoForReg(ins.Args[2].Reg)
			if !ok {
				return fmt.Errorf("amd64 %s invalid dst reg: %q", spec.Op, ins.Raw)
			}
			var p, pty string
			switch ins.Args[0].Kind {
			case asm.OpMem:
				p, pty, err = c.ptrFromMem(ins.Args[0].Mem)
			case asm.OpSym:
				p, err = c.ptrFromSB(ins.Args[0].Sym)
				pty = "ptr"
			default:
				return fmt.Errorf("amd64 %s load expects mem src: %q", spec.Op, ins.Raw)
			}
			if err != nil {
				return err
			}
			ld, out := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.masked.load.v%di%d.p0(%s %s, i32 1, <%d x i1> %%%s, %s zeroinitializer)\n",
				ld, vecTy, lanes, laneBits, pty, p, lanes, mCond, vecTy)
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to %s\n", out, vecTy, ld, dvi.byteVecTy)
			return dvi.storeVec(ins.Args[2].Reg, "%"+out)
		}
		// Store form
		if ins.Args[0].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s store expects Vsrc: %q", spec.Op, ins.Raw)
		}
		svi, ok := c.x86VecInfoForReg(ins.Args[0].Reg)
		if !ok {
			return fmt.Errorf("amd64 %s invalid src reg: %q", spec.Op, ins.Raw)
		}
		sRaw, err := svi.loadReg(ins.Args[0].Reg)
		if err != nil {
			return err
		}
		sb := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", sb, svi.byteVecTy, sRaw, vecTy)
		var p, pty string
		switch ins.Args[2].Kind {
		case asm.OpMem:
			p, pty, err = c.ptrFromMem(ins.Args[2].Mem)
		case asm.OpSym:
			p, err = c.ptrFromSB(ins.Args[2].Sym)
			pty = "ptr"
		default:
			return fmt.Errorf("amd64 %s store expects mem dst: %q", spec.Op, ins.Raw)
		}
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  call void @llvm.masked.store.v%di%d.p0(%s %%%s, %s %s, i32 1, <%d x i1> %%%s)\n",
			lanes, laneBits, vecTy, sb, pty, p, lanes, mCond)
		return nil

	default: // maskmov_di: MASKMOVQ/MASKMOVOU/VMASKMOVDQU maskReg, srcReg -> masked store to (DI)
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects maskReg, srcReg: %q", spec.Op, ins.Raw)
		}
		vi, ok := c.x86VecInfoForReg(ins.Args[1].Reg)
		if !ok {
			return fmt.Errorf("amd64 %s expects vector regs: %q", spec.Op, ins.Raw)
		}
		maskB, err := vi.loadReg(ins.Args[0].Reg)
		if err != nil {
			return err
		}
		srcB, err := vi.loadReg(ins.Args[1].Reg)
		if err != nil {
			return err
		}
		di, err := c.loadReg(asm.DI)
		if err != nil {
			return err
		}
		nB := vi.totalBits / 8
		ptr, cond := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", ptr, di)
		fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, zeroinitializer\n", cond, vi.byteVecTy, maskB)
		fmt.Fprintf(c.b, "  call void @llvm.masked.store.v%di8.p0(%s %s, ptr %%%s, i32 1, <%d x i1> %%%s)\n",
			nB, vi.byteVecTy, srcB, ptr, nB, cond)
		return nil
	}
}

func (c *amd64Ctx) lowerX86M3Scalar(spec asm.OpSpec, ins asm.Instr) error {
	switch spec.LLVMOp {
	case "movbe":
		if len(ins.Args) != 2 {
			return fmt.Errorf("amd64 %s expects 2 operands: %q", spec.Op, ins.Raw)
		}
		ty := x86LLVMIntType(spec.Width)
		v, err := c.evalIntSized(ins.Args[0], ty)
		if err != nil {
			return err
		}
		sw := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.bswap.%s(%s %s)\n", sw, ty, ty, ty, v)
		if ins.Args[1].Kind == asm.OpReg {
			return c.storeRegSized(ins.Args[1].Reg, ty, "%"+sw)
		}
		var p, pty string
		switch ins.Args[1].Kind {
		case asm.OpMem:
			p, pty, err = c.ptrFromMem(ins.Args[1].Mem)
		case asm.OpSym:
			p, err = c.ptrFromSB(ins.Args[1].Sym)
			pty = "ptr"
		default:
			return fmt.Errorf("amd64 %s unsupported dst: %q", spec.Op, ins.Raw)
		}
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store %s %%%s, %s %s, align 1\n", ty, sw, pty, p)
		return nil

	case "movnti":
		if len(ins.Args) != 2 {
			return fmt.Errorf("amd64 %s expects reg, mem: %q", spec.Op, ins.Raw)
		}
		ty := x86LLVMIntType(spec.Width)
		v, err := c.evalIntSized(ins.Args[0], ty)
		if err != nil {
			return err
		}
		var p, pty string
		switch ins.Args[1].Kind {
		case asm.OpMem:
			p, pty, err = c.ptrFromMem(ins.Args[1].Mem)
		case asm.OpSym:
			p, err = c.ptrFromSB(ins.Args[1].Sym)
			pty = "ptr"
		default:
			return fmt.Errorf("amd64 %s expects mem dst: %q", spec.Op, ins.Raw)
		}
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store %s %s, %s %s, align 1\n", ty, v, pty, p)
		return nil

	case "pdep_pext":
		// PDEP/PEXT mask, src, dst (BMI2; pure target-independent bit loop)
		if len(ins.Args) != 3 || ins.Args[2].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects mask, src, dstReg: %q", spec.Op, ins.Raw)
		}
		bits := int(spec.Width)
		ty := x86LLVMIntType(spec.Width)
		maskV, err := c.evalIntSized(ins.Args[0], ty)
		if err != nil {
			return err
		}
		srcV, err := c.evalIntSized(ins.Args[1], ty)
		if err != nil {
			return err
		}
		// Compact target-independent PDEP/PEXT using bit-by-bit selection.
		acc := "0"
		kPos := "0"
		isPext := spec.SubOp == 1
		for i := 0; i < bits; i++ {
			mSh, mBit, mNZ, nK := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %d\n", mSh, ty, maskV, i)
			fmt.Fprintf(c.b, "  %%%s = and %s %%%s, 1\n", mBit, ty, mSh)
			fmt.Fprintf(c.b, "  %%%s = icmp ne %s %%%s, 0\n", mNZ, ty, mBit)
			if isPext {
				sSh, sBit, put, sel, orv := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %d\n", sSh, ty, srcV, i)
				fmt.Fprintf(c.b, "  %%%s = and %s %%%s, 1\n", sBit, ty, sSh)
				fmt.Fprintf(c.b, "  %%%s = shl %s %%%s, %s\n", put, ty, sBit, kPos)
				fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %%%s, %s 0\n", sel, mNZ, ty, put, ty)
				fmt.Fprintf(c.b, "  %%%s = or %s %s, %%%s\n", orv, ty, acc, sel)
				acc = "%" + orv
			} else {
				sSh, sBit, put, sel, orv := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %s\n", sSh, ty, srcV, kPos)
				fmt.Fprintf(c.b, "  %%%s = and %s %%%s, 1\n", sBit, ty, sSh)
				fmt.Fprintf(c.b, "  %%%s = shl %s %%%s, %d\n", put, ty, sBit, i)
				fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %%%s, %s 0\n", sel, mNZ, ty, put, ty)
				fmt.Fprintf(c.b, "  %%%s = or %s %s, %%%s\n", orv, ty, acc, sel)
				acc = "%" + orv
			}
			fmt.Fprintf(c.b, "  %%%s = add %s %s, %%%s\n", nK, ty, kPos, mBit)
			kPos = "%" + nK
		}
		return c.storeRegSized(ins.Args[2].Reg, ty, acc)

	case "div_idiv":
		if len(ins.Args) != 1 {
			return fmt.Errorf("amd64 %s expects 1 operand: %q", spec.Op, ins.Raw)
		}
		bits := int(spec.Width)
		ty := x86LLVMIntType(spec.Width)
		wideTy := fmt.Sprintf("i%d", bits*2)
		divOp, remOp, extOp := "udiv", "urem", "zext"
		if spec.Signed {
			divOp, remOp, extOp = "sdiv", "srem", "sext"
		}
		dv, err := c.evalIntSized(ins.Args[0], ty)
		if err != nil {
			return err
		}
		ax64, err := c.loadReg(asm.AX)
		if err != nil {
			return err
		}
		dx64, err := c.loadReg(asm.DX)
		if err != nil {
			return err
		}
		axVal, dxVal := ax64, dx64
		if bits == 32 {
			ta, td := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", ta, ax64)
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", td, dx64)
			axVal, dxVal = "%"+ta, "%"+td
		}
		hiW, hiSh, loW, num, den, qW, rW, q, r := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", hiW, ty, dxVal, wideTy)
		fmt.Fprintf(c.b, "  %%%s = shl %s %%%s, %d\n", hiSh, wideTy, hiW, bits)
		fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", loW, ty, axVal, wideTy)
		fmt.Fprintf(c.b, "  %%%s = or %s %%%s, %%%s\n", num, wideTy, hiSh, loW)
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", den, extOp, ty, dv, wideTy)
		fmt.Fprintf(c.b, "  %%%s = %s %s %%%s, %%%s\n", qW, divOp, wideTy, num, den)
		fmt.Fprintf(c.b, "  %%%s = %s %s %%%s, %%%s\n", rW, remOp, wideTy, num, den)
		fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", q, wideTy, qW, ty)
		fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", r, wideTy, rW, ty)
		if err := c.storeRegSized(asm.AX, ty, "%"+q); err != nil {
			return err
		}
		return c.storeRegSized(asm.DX, ty, "%"+r)

	case "cwd":
		ax, err := c.loadReg(asm.AX)
		if err != nil {
			return err
		}
		tr, as := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i16\n", tr, ax)
		fmt.Fprintf(c.b, "  %%%s = ashr i16 %%%s, 15\n", as, tr)
		return c.storeRegSized(asm.DX, asm.I16, "%"+as)

	case "lahf":
		zf := c.loadFlag(c.flagsZSlot)
		cf := c.loadFlag(c.flagsCFSlot)
		z8, c8, zSh, flags, res := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i1 %s to i8\n", z8, zf)
		fmt.Fprintf(c.b, "  %%%s = zext i1 %s to i8\n", c8, cf)
		fmt.Fprintf(c.b, "  %%%s = shl i8 %%%s, 6\n", zSh, z8)
		fmt.Fprintf(c.b, "  %%%s = or i8 %%%s, %%%s\n", flags, zSh, c8)
		fmt.Fprintf(c.b, "  %%%s = or i8 %%%s, 2\n", res, flags)
		return c.storeRegSized(asm.AH, asm.I8, "%"+res)

	case "sahf":
		ah64, err := c.loadReg(asm.AH)
		if err != nil {
			return err
		}
		cfB, cf, zfSh, zfB, zf := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, 1\n", cfB, ah64)
		fmt.Fprintf(c.b, "  %%%s = icmp ne i64 %%%s, 0\n", cf, cfB)
		fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, 6\n", zfSh, ah64)
		fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, 1\n", zfB, zfSh)
		fmt.Fprintf(c.b, "  %%%s = icmp ne i64 %%%s, 0\n", zf, zfB)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zf, c.flagsZSlot)
		return nil

	case "pushw", "pushfw":
		val := "0"
		if spec.LLVMOp == "pushw" {
			if len(ins.Args) != 1 {
				return fmt.Errorf("amd64 PUSHW expects 1 operand: %q", ins.Raw)
			}
			var err error
			val, err = c.evalIntSized(ins.Args[0], asm.I16)
			if err != nil {
				return err
			}
		}
		sp, err := c.loadReg(asm.SP)
		if err != nil {
			return err
		}
		nsp, ptr := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i64 %s, 2\n", nsp, sp)
		if err := c.storeRegUnchecked(asm.SP, "%"+nsp); err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %%%s to ptr\n", ptr, nsp)
		fmt.Fprintf(c.b, "  store i16 %s, ptr %%%s, align 1\n", val, ptr)
		return nil

	case "popw", "popfw":
		sp, err := c.loadReg(asm.SP)
		if err != nil {
			return err
		}
		ptr, ld, nsp := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", ptr, sp)
		fmt.Fprintf(c.b, "  %%%s = load i16, ptr %%%s, align 1\n", ld, ptr)
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, 2\n", nsp, sp)
		if err := c.storeRegUnchecked(asm.SP, "%"+nsp); err != nil {
			return err
		}
		if spec.LLVMOp == "popfw" {
			return nil
		}
		if len(ins.Args) != 1 {
			return fmt.Errorf("amd64 POPW expects 1 operand: %q", ins.Raw)
		}
		if ins.Args[0].Kind == asm.OpReg {
			if isX86SystemOrSegIdent(string(ins.Args[0].Reg)) {
				return nil
			}
			return c.storeRegSized(ins.Args[0].Reg, asm.I16, "%"+ld)
		}
		if ins.Args[0].Kind == asm.OpIdent && isX86SystemOrSegIdent(ins.Args[0].Ident) {
			return nil
		}
		if isX86MemOp(ins.Args[0]) {
			p, pty, err := c.resolveMemPtr(ins.Args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(c.b, "  store i16 %%%s, %s %s, align 1\n", ld, pty, p)
			return nil
		}
		return fmt.Errorf("amd64 POPW unsupported dst: %q", ins.Raw)

	default: // xlat
		bx, err := c.loadReg(asm.BX)
		if err != nil {
			return err
		}
		al64, err := c.loadReg(asm.AL)
		if err != nil {
			return err
		}
		off, addr, ptr, ld := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, 255\n", off, al64)
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, %%%s\n", addr, bx, off)
		fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %%%s to ptr\n", ptr, addr)
		fmt.Fprintf(c.b, "  %%%s = load i8, ptr %%%s, align 1\n", ld, ptr)
		return c.storeRegSized(asm.AL, asm.I8, "%"+ld)
	}
}

func (c *amd64Ctx) lowerX86M3String(spec asm.OpSpec, ins asm.Instr) error {
	prefix := c.repeatPrefix
	c.repeatPrefix = ""
	if len(ins.Args) != 0 {
		return fmt.Errorf("amd64 %s takes no operands: %q", spec.Op, ins.Raw)
	}
	if prefix == "REPN" && spec.LLVMOp != "scas" && spec.LLVMOp != "cmps" {
		return fmt.Errorf("386 REPN is unsupported for %s", spec.Op)
	}
	if prefix == "" {
		return c.lowerX86M3StringStep(spec)
	}
	hdr := "rep_hdr_" + c.newTmp()
	body := "rep_body_" + c.newTmp()
	done := "rep_done_" + c.newTmp()
	fmt.Fprintf(c.b, "  br label %%%s\n%s:\n", hdr, hdr)
	cntTy := asm.I64
	if c.goarch == "386" {
		cntTy = asm.I32
	}
	cx, err := c.evalIntSized(asm.Operand{Kind: asm.OpReg, Reg: asm.CX}, cntTy)
	if err != nil {
		return err
	}
	nonzero := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ne %s %s, 0\n", nonzero, cntTy, cx)
	fmt.Fprintf(c.b, "  br i1 %%%s, label %%%s, label %%%s\n%s:\n", nonzero, body, done, body)
	if err := c.lowerX86M3StringStep(spec); err != nil {
		return err
	}
	dec := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub %s %s, 1\n", dec, cntTy, cx)
	if err := c.storeRegSized(asm.CX, cntTy, "%"+dec); err != nil {
		return err
	}
	if spec.LLVMOp == "scas" || spec.LLVMOp == "cmps" {
		zf := c.loadFlag(c.flagsZSlot)
		if prefix == "REPN" {
			fmt.Fprintf(c.b, "  br i1 %s, label %%%s, label %%%s\n%s:\n", zf, done, hdr, done)
		} else {
			fmt.Fprintf(c.b, "  br i1 %s, label %%%s, label %%%s\n%s:\n", zf, hdr, done, done)
		}
	} else {
		fmt.Fprintf(c.b, "  br label %%%s\n%s:\n", hdr, done)
	}
	return nil
}

func (c *amd64Ctx) advanceStringReg(reg asm.Reg, cur string, step int64) error {
	return c.storeStringIndex(reg, cur, fmt.Sprintf("%d", step), c.loadDirectionFlag())
}

func (c *amd64Ctx) lowerX86M3StringStep(spec asm.OpSpec) error {
	ty := x86LLVMIntType(spec.Width)
	step := int64(spec.Width / 8)
	switch spec.LLVMOp {
	case "lods":
		si, err := c.loadReg(asm.SI)
		if err != nil {
			return err
		}
		ptr, ld := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", ptr, si)
		fmt.Fprintf(c.b, "  %%%s = load %s, ptr %%%s, align 1\n", ld, ty, ptr)
		if err := c.advanceStringReg(asm.SI, si, step); err != nil {
			return err
		}
		return c.storeRegSized(asm.AX, ty, "%"+ld)
	case "stos":
		di, err := c.loadReg(asm.DI)
		if err != nil {
			return err
		}
		ax, err := c.loadReg(asm.AX)
		if err != nil {
			return err
		}
		v := ax
		if ty != asm.I64 {
			tr := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", tr, ax, ty)
			v = "%" + tr
		}
		ptr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", ptr, di)
		fmt.Fprintf(c.b, "  store %s %s, ptr %%%s, align 1\n", ty, v, ptr)
		return c.advanceStringReg(asm.DI, di, step)
	case "movs":
		si, err := c.loadReg(asm.SI)
		if err != nil {
			return err
		}
		di, err := c.loadReg(asm.DI)
		if err != nil {
			return err
		}
		ps, pd, ld := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", ps, si)
		fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pd, di)
		fmt.Fprintf(c.b, "  %%%s = load %s, ptr %%%s, align 1\n", ld, ty, ps)
		fmt.Fprintf(c.b, "  store %s %%%s, ptr %%%s, align 1\n", ty, ld, pd)
		if err := c.advanceStringReg(asm.SI, si, step); err != nil {
			return err
		}
		return c.advanceStringReg(asm.DI, di, step)
	case "scas":
		di, err := c.loadReg(asm.DI)
		if err != nil {
			return err
		}
		ax, err := c.loadReg(asm.AX)
		if err != nil {
			return err
		}
		v := ax
		if ty != asm.I64 {
			tr := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", tr, ax, ty)
			v = "%" + tr
		}
		pd, ld, eq, ult := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pd, di)
		fmt.Fprintf(c.b, "  %%%s = load %s, ptr %%%s, align 1\n", ld, ty, pd)
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, %%%s\n", eq, ty, v, ld)
		fmt.Fprintf(c.b, "  %%%s = icmp ult %s %s, %%%s\n", ult, ty, v, ld)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", eq, c.flagsZSlot)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", ult, c.flagsCFSlot)
		return c.advanceStringReg(asm.DI, di, step)
	default: // cmps
		si, err := c.loadReg(asm.SI)
		if err != nil {
			return err
		}
		di, err := c.loadReg(asm.DI)
		if err != nil {
			return err
		}
		ps, pd, ls, ld, eq, ult := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", ps, si)
		fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pd, di)
		fmt.Fprintf(c.b, "  %%%s = load %s, ptr %%%s, align 1\n", ls, ty, ps)
		fmt.Fprintf(c.b, "  %%%s = load %s, ptr %%%s, align 1\n", ld, ty, pd)
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, %%%s\n", eq, ty, ls, ld)
		fmt.Fprintf(c.b, "  %%%s = icmp ult %s %%%s, %%%s\n", ult, ty, ls, ld)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", eq, c.flagsZSlot)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", ult, c.flagsCFSlot)
		if err := c.advanceStringReg(asm.SI, si, step); err != nil {
			return err
		}
		return c.advanceStringReg(asm.DI, di, step)
	}
}

func (c *amd64Ctx) lowerX86M3Sys(spec asm.OpSpec, ins asm.Instr) error {
	if len(ins.Args) != 1 {
		return fmt.Errorf("amd64 %s expects 1 operand: %q", spec.Op, ins.Raw)
	}
	if spec.LLVMOp == "sys_mem" {
		if ins.Args[0].Kind != asm.OpMem && ins.Args[0].Kind != asm.OpSym {
			return fmt.Errorf("amd64 %s expects memory operand: %q", spec.Op, ins.Raw)
		}
		if spec.SubOp == 1 {
			// SGDT / SIDT: zero-write 10-byte descriptor slot
			var p, pty string
			var err error
			if ins.Args[0].Kind == asm.OpMem {
				p, pty, err = c.ptrFromMem(ins.Args[0].Mem)
			} else {
				p, err = c.ptrFromSB(ins.Args[0].Sym)
				pty = "ptr"
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(c.b, "  store i64 0, %s %s, align 1\n", pty, p)
		}
		return nil
	}
	// LLDT / LMSW / LTR / TPAUSE / UMWAIT
	if ins.Args[0].Kind != asm.OpReg && ins.Args[0].Kind != asm.OpMem && ins.Args[0].Kind != asm.OpSym {
		return fmt.Errorf("amd64 %s expects reg/mem operand: %q", spec.Op, ins.Raw)
	}
	return nil
}
