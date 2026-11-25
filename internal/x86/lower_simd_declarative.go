package x86

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// x86ExtraSIMDSpecs declaratively models K-mask ops, scalar FP (*SS/V*SS/V*SD),
// saturating/unary/compare/shuffle/extend/pack/blend/extract/insert/shift/crypto
// SIMD families so a few parameterized templates cover hundreds of forms.
var x86ExtraSIMDSpecs = []asm.OpSpec{
	// AVX-512 K-mask ALU
	{Op: "KADDB", Family: asm.FamilyMask, Width: 8, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "add"},
	{Op: "KADDW", Family: asm.FamilyMask, Width: 16, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "add"},
	{Op: "KADDD", Family: asm.FamilyMask, Width: 32, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "add"},
	{Op: "KADDQ", Family: asm.FamilyMask, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "add"},
	{Op: "KANDB", Family: asm.FamilyMask, Width: 8, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "and"},
	{Op: "KANDW", Family: asm.FamilyMask, Width: 16, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "and"},
	{Op: "KANDD", Family: asm.FamilyMask, Width: 32, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "and"},
	{Op: "KANDQ", Family: asm.FamilyMask, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "and"},
	{Op: "KANDNB", Family: asm.FamilyMask, Width: 8, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "andn"},
	{Op: "KANDNW", Family: asm.FamilyMask, Width: 16, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "andn"},
	{Op: "KANDND", Family: asm.FamilyMask, Width: 32, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "andn"},
	{Op: "KANDNQ", Family: asm.FamilyMask, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "andn"},
	{Op: "KORB", Family: asm.FamilyMask, Width: 8, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "or"},
	{Op: "KORW", Family: asm.FamilyMask, Width: 16, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "or"},
	{Op: "KORD", Family: asm.FamilyMask, Width: 32, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "or"},
	{Op: "KORQ", Family: asm.FamilyMask, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "or"},
	{Op: "KXORB", Family: asm.FamilyMask, Width: 8, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "xor"},
	{Op: "KXORW", Family: asm.FamilyMask, Width: 16, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "xor"},
	{Op: "KXORD", Family: asm.FamilyMask, Width: 32, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "xor"},
	{Op: "KXNORB", Family: asm.FamilyMask, Width: 8, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "xnor"},
	{Op: "KXNORW", Family: asm.FamilyMask, Width: 16, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "xnor"},
	{Op: "KXNORD", Family: asm.FamilyMask, Width: 32, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "xnor"},
	{Op: "KXNORQ", Family: asm.FamilyMask, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "xnor"},
	{Op: "KNOTB", Family: asm.FamilyMask, Width: 8, Effect: asm.EffectWriteOnly, LLVMOp: "not"},
	{Op: "KNOTW", Family: asm.FamilyMask, Width: 16, Effect: asm.EffectWriteOnly, LLVMOp: "not"},
	{Op: "KNOTD", Family: asm.FamilyMask, Width: 32, Effect: asm.EffectWriteOnly, LLVMOp: "not"},
	{Op: "KNOTQ", Family: asm.FamilyMask, Width: 64, Effect: asm.EffectWriteOnly, LLVMOp: "not"},
	{Op: "KMOVD", Family: asm.FamilyMask, Width: 32, Effect: asm.EffectWriteOnly, LLVMOp: "mov"},
	{Op: "KSHIFTLB", Family: asm.FamilyMask, Width: 8, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "shl"},
	{Op: "KSHIFTLW", Family: asm.FamilyMask, Width: 16, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "shl"},
	{Op: "KSHIFTLD", Family: asm.FamilyMask, Width: 32, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "shl"},
	{Op: "KSHIFTLQ", Family: asm.FamilyMask, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "shl"},
	{Op: "KSHIFTRB", Family: asm.FamilyMask, Width: 8, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "lshr"},
	{Op: "KSHIFTRW", Family: asm.FamilyMask, Width: 16, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "lshr"},
	{Op: "KSHIFTRD", Family: asm.FamilyMask, Width: 32, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "lshr"},
	{Op: "KSHIFTRQ", Family: asm.FamilyMask, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "lshr"},

	// Scalar single/double FP (SSE + VEX/EVEX)
	{Op: "MOVSS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectPreserveUpper, LLVMOp: "movs"},
	{Op: "VMOVSS", Family: asm.FamilyFP, Width: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "movs"},
	{Op: "VMOVSD", Family: asm.FamilyFP, Width: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "movs"},
	{Op: "ADDSS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "fadd"},
	{Op: "SUBSS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "fsub"},
	{Op: "MULSS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "fmul"},
	{Op: "DIVSS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "fdiv"},
	{Op: "MINSS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "fmin"},
	{Op: "MAXSS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "fmax"},
	{Op: "SQRTSS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectPreserveUpper, LLVMOp: "sqrt"},
	{Op: "RCPSS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectPreserveUpper, LLVMOp: "rcp"},
	{Op: "RSQRTSS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectPreserveUpper, LLVMOp: "rsqrt"},
	{Op: "COMISS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite, LLVMOp: "comi"},
	{Op: "UCOMISS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite, LLVMOp: "comi"},
	{Op: "UCOMISD", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite, LLVMOp: "comi"},
	{Op: "VADDSS", Family: asm.FamilyFP, Width: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "fadd"},
	{Op: "VSUBSS", Family: asm.FamilyFP, Width: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "fsub"},
	{Op: "VMULSS", Family: asm.FamilyFP, Width: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "fmul"},
	{Op: "VDIVSS", Family: asm.FamilyFP, Width: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "fdiv"},
	{Op: "VMINSS", Family: asm.FamilyFP, Width: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "fmin"},
	{Op: "VMAXSS", Family: asm.FamilyFP, Width: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "fmax"},
	{Op: "VSQRTSS", Family: asm.FamilyFP, Width: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "sqrt"},
	{Op: "VRCPSS", Family: asm.FamilyFP, Width: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "rcp"},
	{Op: "VRSQRTSS", Family: asm.FamilyFP, Width: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "rsqrt"},
	{Op: "VADDSD", Family: asm.FamilyFP, Width: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "fadd"},
	{Op: "VSUBSD", Family: asm.FamilyFP, Width: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "fsub"},
	{Op: "VMULSD", Family: asm.FamilyFP, Width: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "fmul"},
	{Op: "VDIVSD", Family: asm.FamilyFP, Width: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "fdiv"},
	{Op: "VMINSD", Family: asm.FamilyFP, Width: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "fmin"},
	{Op: "VMAXSD", Family: asm.FamilyFP, Width: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "fmax"},
	{Op: "VSQRTSD", Family: asm.FamilyFP, Width: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "sqrt"},
	{Op: "VCOMISS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite, LLVMOp: "comi"},
	{Op: "VUCOMISS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite, LLVMOp: "comi"},
	{Op: "VCOMISD", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite, LLVMOp: "comi"},
	{Op: "VUCOMISD", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite, LLVMOp: "comi"},
	{Op: "CVTSL2SS", Family: asm.FamilyFP, Width: 32, SrcWidth: 32, Float: true, Signed: true, Effect: asm.EffectPreserveUpper, LLVMOp: "i2f"},
	{Op: "CVTSQ2SS", Family: asm.FamilyFP, Width: 32, SrcWidth: 64, Float: true, Signed: true, Effect: asm.EffectPreserveUpper, LLVMOp: "i2f"},
	{Op: "VCVTSI2SSL", Family: asm.FamilyFP, Width: 32, SrcWidth: 32, Float: true, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "i2f"},
	{Op: "VCVTSI2SSQ", Family: asm.FamilyFP, Width: 32, SrcWidth: 64, Float: true, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "i2f"},
	{Op: "VCVTSI2SDL", Family: asm.FamilyFP, Width: 64, SrcWidth: 32, Float: true, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "i2f"},
	{Op: "VCVTSI2SDQ", Family: asm.FamilyFP, Width: 64, SrcWidth: 64, Float: true, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "i2f"},
	{Op: "CVTSS2SD", Family: asm.FamilyFP, Width: 64, SrcWidth: 32, Float: true, Effect: asm.EffectPreserveUpper, LLVMOp: "f2f"},
	{Op: "CVTSD2SS", Family: asm.FamilyFP, Width: 32, SrcWidth: 64, Float: true, Effect: asm.EffectPreserveUpper, LLVMOp: "f2f"},
	{Op: "VCVTSS2SD", Family: asm.FamilyFP, Width: 64, SrcWidth: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "f2f"},
	{Op: "VCVTSD2SS", Family: asm.FamilyFP, Width: 32, SrcWidth: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "f2f"},
	{Op: "CVTSS2SL", Family: asm.FamilyFP, Width: 32, SrcWidth: 32, Signed: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "f2i"},
	{Op: "CVTSS2SQ", Family: asm.FamilyFP, Width: 64, SrcWidth: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "f2i"},
	{Op: "CVTTSS2SL", Family: asm.FamilyFP, Width: 32, SrcWidth: 32, Signed: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "f2i"},
	{Op: "CVTTSS2SQ", Family: asm.FamilyFP, Width: 64, SrcWidth: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "f2i"},
	{Op: "CVTSD2SQ", Family: asm.FamilyFP, Width: 64, SrcWidth: 64, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "f2i"},
	{Op: "CVTTSD2SL", Family: asm.FamilyFP, Width: 32, SrcWidth: 64, Signed: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "f2i"},

	// Packed Unary (PABS/VPABS, SQRTPS/PD, RCPPS/RSQRTPS + V*)
	{Op: "PABSB", Family: asm.FamilyVecUnary, LaneBits: 8, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "abs"},
	{Op: "PABSW", Family: asm.FamilyVecUnary, LaneBits: 16, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "abs"},
	{Op: "PABSD", Family: asm.FamilyVecUnary, LaneBits: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "abs"},
	{Op: "VPABSB", Family: asm.FamilyVecUnary, LaneBits: 8, Signed: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "abs"},
	{Op: "VPABSW", Family: asm.FamilyVecUnary, LaneBits: 16, Signed: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "abs"},
	{Op: "VPABSD", Family: asm.FamilyVecUnary, LaneBits: 32, Signed: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "abs"},
	{Op: "VPABSQ", Family: asm.FamilyVecUnary, LaneBits: 64, Signed: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "abs"},
	{Op: "VPOPCNTB", Family: asm.FamilyVecUnary, LaneBits: 8, Effect: asm.EffectWriteZeroUpper, LLVMOp: "ctpop"},
	{Op: "VPOPCNTW", Family: asm.FamilyVecUnary, LaneBits: 16, Effect: asm.EffectWriteZeroUpper, LLVMOp: "ctpop"},
	{Op: "VPOPCNTD", Family: asm.FamilyVecUnary, LaneBits: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "ctpop"},
	{Op: "VPOPCNTQ", Family: asm.FamilyVecUnary, LaneBits: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "ctpop"},
	{Op: "SQRTPS", Family: asm.FamilyVecUnary, LaneBits: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "sqrt"},
	{Op: "SQRTPD", Family: asm.FamilyVecUnary, LaneBits: 64, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "sqrt"},
	{Op: "VSQRTPS", Family: asm.FamilyVecUnary, LaneBits: 32, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "sqrt"},
	{Op: "VSQRTPD", Family: asm.FamilyVecUnary, LaneBits: 64, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "sqrt"},
	{Op: "RCPPS", Family: asm.FamilyVecUnary, LaneBits: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "rcp"},
	{Op: "VRCPPS", Family: asm.FamilyVecUnary, LaneBits: 32, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "rcp"},
	{Op: "RSQRTPS", Family: asm.FamilyVecUnary, LaneBits: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "rsqrt"},
	{Op: "VRSQRTPS", Family: asm.FamilyVecUnary, LaneBits: 32, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "rsqrt"},

	// Packed sign/zero extend (24 ops!)
	{Op: "PMOVSXBW", Family: asm.FamilyVecUnary, SrcWidth: 8, LaneBits: 16, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "vext"},
	{Op: "PMOVSXBD", Family: asm.FamilyVecUnary, SrcWidth: 8, LaneBits: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "vext"},
	{Op: "PMOVSXBQ", Family: asm.FamilyVecUnary, SrcWidth: 8, LaneBits: 64, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "vext"},
	{Op: "PMOVSXWD", Family: asm.FamilyVecUnary, SrcWidth: 16, LaneBits: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "vext"},
	{Op: "PMOVSXWQ", Family: asm.FamilyVecUnary, SrcWidth: 16, LaneBits: 64, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "vext"},
	{Op: "PMOVSXDQ", Family: asm.FamilyVecUnary, SrcWidth: 32, LaneBits: 64, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "vext"},
	{Op: "PMOVZXBW", Family: asm.FamilyVecUnary, SrcWidth: 8, LaneBits: 16, Effect: asm.EffectWriteOnly, LLVMOp: "vext"},
	{Op: "PMOVZXBD", Family: asm.FamilyVecUnary, SrcWidth: 8, LaneBits: 32, Effect: asm.EffectWriteOnly, LLVMOp: "vext"},
	{Op: "PMOVZXBQ", Family: asm.FamilyVecUnary, SrcWidth: 8, LaneBits: 64, Effect: asm.EffectWriteOnly, LLVMOp: "vext"},
	{Op: "PMOVZXWD", Family: asm.FamilyVecUnary, SrcWidth: 16, LaneBits: 32, Effect: asm.EffectWriteOnly, LLVMOp: "vext"},
	{Op: "PMOVZXWQ", Family: asm.FamilyVecUnary, SrcWidth: 16, LaneBits: 64, Effect: asm.EffectWriteOnly, LLVMOp: "vext"},
	{Op: "PMOVZXDQ", Family: asm.FamilyVecUnary, SrcWidth: 32, LaneBits: 64, Effect: asm.EffectWriteOnly, LLVMOp: "vext"},
	{Op: "VPMOVSXBW", Family: asm.FamilyVecUnary, SrcWidth: 8, LaneBits: 16, Signed: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vext"},
	{Op: "VPMOVSXBD", Family: asm.FamilyVecUnary, SrcWidth: 8, LaneBits: 32, Signed: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vext"},
	{Op: "VPMOVSXBQ", Family: asm.FamilyVecUnary, SrcWidth: 8, LaneBits: 64, Signed: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vext"},
	{Op: "VPMOVSXWD", Family: asm.FamilyVecUnary, SrcWidth: 16, LaneBits: 32, Signed: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vext"},
	{Op: "VPMOVSXWQ", Family: asm.FamilyVecUnary, SrcWidth: 16, LaneBits: 64, Signed: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vext"},
	{Op: "VPMOVSXDQ", Family: asm.FamilyVecUnary, SrcWidth: 32, LaneBits: 64, Signed: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vext"},
	{Op: "VPMOVZXBW", Family: asm.FamilyVecUnary, SrcWidth: 8, LaneBits: 16, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vext"},
	{Op: "VPMOVZXBD", Family: asm.FamilyVecUnary, SrcWidth: 8, LaneBits: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vext"},
	{Op: "VPMOVZXBQ", Family: asm.FamilyVecUnary, SrcWidth: 8, LaneBits: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vext"},
	{Op: "VPMOVZXWD", Family: asm.FamilyVecUnary, SrcWidth: 16, LaneBits: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vext"},
	{Op: "VPMOVZXWQ", Family: asm.FamilyVecUnary, SrcWidth: 16, LaneBits: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vext"},
	{Op: "VPMOVZXDQ", Family: asm.FamilyVecUnary, SrcWidth: 32, LaneBits: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vext"},

	// Vector moves & masks
	{Op: "MOVUPD", Family: asm.FamilyMove, Width: 128, Effect: asm.EffectWriteOnly, LLVMOp: "vmov"},
	{Op: "VMOVUPD", Family: asm.FamilyMove, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vmov"},
	{Op: "VMOVUPS", Family: asm.FamilyMove, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vmov"},
	{Op: "VMOVDQU8", Family: asm.FamilyMove, LaneBits: 8, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vmov"},
	{Op: "VMOVDQU16", Family: asm.FamilyMove, LaneBits: 16, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vmov"},
	{Op: "VMOVDQU32", Family: asm.FamilyMove, LaneBits: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vmov"},
	{Op: "VMOVDQA32", Family: asm.FamilyMove, LaneBits: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vmov"},
	{Op: "MOVHLPS", Family: asm.FamilyVecShuffle, LaneBits: 64, Effect: asm.EffectReadWrite, LLVMOp: "movhlps"},
	{Op: "MOVLHPS", Family: asm.FamilyVecShuffle, LaneBits: 64, Effect: asm.EffectReadWrite, LLVMOp: "movlhps"},
	{Op: "VMOVHLPS", Family: asm.FamilyVecShuffle, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "movhlps"},
	{Op: "VMOVLHPS", Family: asm.FamilyVecShuffle, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "movlhps"},
	{Op: "MOVMSKPS", Family: asm.FamilyVecShuffle, LaneBits: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "movmsk"},
	{Op: "MOVMSKPD", Family: asm.FamilyVecShuffle, LaneBits: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "movmsk"},
	{Op: "VMOVMSKPS", Family: asm.FamilyVecShuffle, LaneBits: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "movmsk"},
	{Op: "VMOVMSKPD", Family: asm.FamilyVecShuffle, LaneBits: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "movmsk"},
	{Op: "PMOVMSKB", Family: asm.FamilyVecShuffle, LaneBits: 8, Effect: asm.EffectWriteZeroUpper, LLVMOp: "movmsk"},
	{Op: "VPMOVMSKB", Family: asm.FamilyVecShuffle, LaneBits: 8, Effect: asm.EffectWriteZeroUpper, LLVMOp: "movmsk"},

	// Shuffles, blends, unpacks, packs, aligns, permutes, inserts, extracts
	{Op: "PSHUFD", Family: asm.FamilyVecShuffle, LaneBits: 32, Effect: asm.EffectWriteOnly, LLVMOp: "pshufd"},
	{Op: "PSHUFL", Family: asm.FamilyVecShuffle, LaneBits: 32, Effect: asm.EffectWriteOnly, LLVMOp: "pshufd"},
	{Op: "VPSHUFD", Family: asm.FamilyVecShuffle, LaneBits: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "pshufd"},
	{Op: "VPSHUFB", Family: asm.FamilyVecShuffle, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpshufb"},
	{Op: "VPALIGNR", Family: asm.FamilyVecShuffle, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpalignr"},
	{Op: "PSHUFHW", Family: asm.FamilyVecShuffle, LaneBits: 16, Effect: asm.EffectWriteOnly, LLVMOp: "pshufw_hi"},
	{Op: "PSHUFLW", Family: asm.FamilyVecShuffle, LaneBits: 16, Effect: asm.EffectWriteOnly, LLVMOp: "pshufw_lo"},
	{Op: "VPSHUFLW", Family: asm.FamilyVecShuffle, LaneBits: 16, Effect: asm.EffectWriteZeroUpper, LLVMOp: "pshufw_lo"},
	{Op: "VPSHUFHW", Family: asm.FamilyVecShuffle, LaneBits: 16, Effect: asm.EffectWriteZeroUpper, LLVMOp: "pshufw_hi"},
	{Op: "SHUFPD", Family: asm.FamilyVecShuffle, LaneBits: 64, Effect: asm.EffectReadWrite, LLVMOp: "shufp"},
	{Op: "VSHUFPS", Family: asm.FamilyVecShuffle, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "shufp"},
	{Op: "VSHUFPD", Family: asm.FamilyVecShuffle, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "shufp"},
	{Op: "UNPCKLPS", Family: asm.FamilyVecShuffle, LaneBits: 32, Effect: asm.EffectReadWrite, LLVMOp: "unpckl"},
	{Op: "UNPCKHPS", Family: asm.FamilyVecShuffle, LaneBits: 32, Effect: asm.EffectReadWrite, LLVMOp: "unpckh"},
	{Op: "UNPCKLPD", Family: asm.FamilyVecShuffle, LaneBits: 64, Effect: asm.EffectReadWrite, LLVMOp: "unpckl"},
	{Op: "UNPCKHPD", Family: asm.FamilyVecShuffle, LaneBits: 64, Effect: asm.EffectReadWrite, LLVMOp: "unpckh"},
	{Op: "PUNPCKLBW", Family: asm.FamilyVecShuffle, LaneBits: 8, Effect: asm.EffectReadWrite, LLVMOp: "unpckl"},
	{Op: "PUNPCKHBW", Family: asm.FamilyVecShuffle, LaneBits: 8, Effect: asm.EffectReadWrite, LLVMOp: "unpckh"},
	{Op: "PUNPCKLWL", Family: asm.FamilyVecShuffle, LaneBits: 16, Effect: asm.EffectReadWrite, LLVMOp: "unpckl"},
	{Op: "PUNPCKHWL", Family: asm.FamilyVecShuffle, LaneBits: 16, Effect: asm.EffectReadWrite, LLVMOp: "unpckh"},
	{Op: "PUNPCKLLQ", Family: asm.FamilyVecShuffle, LaneBits: 32, Effect: asm.EffectReadWrite, LLVMOp: "unpckl"},
	{Op: "PUNPCKHLQ", Family: asm.FamilyVecShuffle, LaneBits: 32, Effect: asm.EffectReadWrite, LLVMOp: "unpckh"},
	{Op: "PUNPCKHQDQ", Family: asm.FamilyVecShuffle, LaneBits: 64, Effect: asm.EffectReadWrite, LLVMOp: "unpckh"},
	{Op: "VUNPCKLPS", Family: asm.FamilyVecShuffle, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "unpckl"},
	{Op: "VUNPCKHPS", Family: asm.FamilyVecShuffle, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "unpckh"},
	{Op: "VUNPCKLPD", Family: asm.FamilyVecShuffle, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "unpckl"},
	{Op: "VUNPCKHPD", Family: asm.FamilyVecShuffle, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "unpckh"},
	{Op: "VPUNPCKLBW", Family: asm.FamilyVecShuffle, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "unpckl"},
	{Op: "VPUNPCKHBW", Family: asm.FamilyVecShuffle, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "unpckh"},
	{Op: "VPUNPCKLWD", Family: asm.FamilyVecShuffle, LaneBits: 16, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "unpckl"},
	{Op: "VPUNPCKHWD", Family: asm.FamilyVecShuffle, LaneBits: 16, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "unpckh"},
	{Op: "VPUNPCKLDQ", Family: asm.FamilyVecShuffle, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "unpckl"},
	{Op: "VPUNPCKHDQ", Family: asm.FamilyVecShuffle, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "unpckh"},
	{Op: "VPUNPCKLQDQ", Family: asm.FamilyVecShuffle, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "unpckl"},
	{Op: "VPUNPCKHQDQ", Family: asm.FamilyVecShuffle, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "unpckh"},
	{Op: "BLENDPS", Family: asm.FamilyVecShuffle, LaneBits: 32, Effect: asm.EffectReadWrite, LLVMOp: "blend_imm"},
	{Op: "BLENDPD", Family: asm.FamilyVecShuffle, LaneBits: 64, Effect: asm.EffectReadWrite, LLVMOp: "blend_imm"},
	{Op: "VBLENDPS", Family: asm.FamilyVecShuffle, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "blend_imm"},
	{Op: "VBLENDPD", Family: asm.FamilyVecShuffle, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "blend_imm"},
	{Op: "VPBLENDW", Family: asm.FamilyVecShuffle, LaneBits: 16, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "blend_imm"},
	{Op: "VPBLENDD", Family: asm.FamilyVecShuffle, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "blend_imm"},
	{Op: "VPBLENDMB", Family: asm.FamilyVecShuffle, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "blendm"},
	{Op: "VPBLENDMW", Family: asm.FamilyVecShuffle, LaneBits: 16, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "blendm"},
	{Op: "VPBLENDMD", Family: asm.FamilyVecShuffle, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "blendm"},
	{Op: "VPBLENDMQ", Family: asm.FamilyVecShuffle, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "blendm"},
	{Op: "VBLENDMPS", Family: asm.FamilyVecShuffle, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "blendm"},
	{Op: "VBLENDMPD", Family: asm.FamilyVecShuffle, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "blendm"},
	{Op: "VPBROADCASTB", Family: asm.FamilyVecShuffle, LaneBits: 8, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vbroadcast"},
	{Op: "VPBROADCASTW", Family: asm.FamilyVecShuffle, LaneBits: 16, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vbroadcast"},
	{Op: "VPBROADCASTD", Family: asm.FamilyVecShuffle, LaneBits: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vbroadcast"},
	{Op: "VPBROADCASTQ", Family: asm.FamilyVecShuffle, LaneBits: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vbroadcast"},
	{Op: "VBROADCASTSS", Family: asm.FamilyVecShuffle, LaneBits: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vbroadcast"},
	{Op: "VBROADCASTSD", Family: asm.FamilyVecShuffle, LaneBits: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vbroadcast"},
	{Op: "VBROADCASTF32X2", Family: asm.FamilyVecShuffle, LaneBits: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vbroadcast"},
	{Op: "VPTERNLOGD", Family: asm.FamilyVecShuffle, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpternlog"},
	{Op: "VPTERNLOGQ", Family: asm.FamilyVecShuffle, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpternlog"},
	{Op: "VPCMPB", Family: asm.FamilyVecShuffle, LaneBits: 8, Signed: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "vpcmp"},
	{Op: "VPCMPUB", Family: asm.FamilyVecShuffle, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "vpcmp"},
	{Op: "VPCMPW", Family: asm.FamilyVecShuffle, LaneBits: 16, Signed: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "vpcmp"},
	{Op: "VPCMPUW", Family: asm.FamilyVecShuffle, LaneBits: 16, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "vpcmp"},
	{Op: "VPCMPD", Family: asm.FamilyVecShuffle, LaneBits: 32, Signed: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "vpcmp"},
	{Op: "VPCMPUD", Family: asm.FamilyVecShuffle, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "vpcmp"},
	{Op: "VPCMPQ", Family: asm.FamilyVecShuffle, LaneBits: 64, Signed: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "vpcmp"},
	{Op: "VPCMPUQ", Family: asm.FamilyVecShuffle, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "vpcmp"},
	{Op: "VPCOMPRESSB", Family: asm.FamilyVecShuffle, LaneBits: 8, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpcompress"},
	{Op: "VPCOMPRESSW", Family: asm.FamilyVecShuffle, LaneBits: 16, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpcompress"},
	{Op: "VPCOMPRESSD", Family: asm.FamilyVecShuffle, LaneBits: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpcompress"},
	{Op: "VPCOMPRESSQ", Family: asm.FamilyVecShuffle, LaneBits: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpcompress"},
	{Op: "VCOMPRESSPS", Family: asm.FamilyVecShuffle, LaneBits: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpcompress"},
	{Op: "VCOMPRESSPD", Family: asm.FamilyVecShuffle, LaneBits: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpcompress"},
	{Op: "VPERMB", Family: asm.FamilyVecShuffle, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpermb"},
	{Op: "VPERMI2B", Family: asm.FamilyVecShuffle, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpermi2b"},
	{Op: "VGF2P8AFFINEQB", Family: asm.FamilyCrypto, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "gf2affine"},
	{Op: "VGF2P8AFFINEINVQB", Family: asm.FamilyCrypto, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "gf2affineinv"},
	{Op: "VGF2P8MULB", Family: asm.FamilyCrypto, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "gf2mul"},
	{Op: "VSHUFI32X4", Family: asm.FamilyVecShuffle, Width: 128, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vshuf_sub"},
	{Op: "VSHUFF32X4", Family: asm.FamilyVecShuffle, Width: 128, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vshuf_sub"},
	{Op: "VSHUFI64X2", Family: asm.FamilyVecShuffle, Width: 128, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vshuf_sub"},
	{Op: "VSHUFF64X2", Family: asm.FamilyVecShuffle, Width: 128, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vshuf_sub"},
	{Op: "MOVSLDUP", Family: asm.FamilyVecShuffle, LaneBits: 32, Effect: asm.EffectWriteOnly, LLVMOp: "movsldup"},
	{Op: "VMOVSLDUP", Family: asm.FamilyVecShuffle, LaneBits: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "movsldup"},
	{Op: "MOVSHDUP", Family: asm.FamilyVecShuffle, LaneBits: 32, Effect: asm.EffectWriteOnly, LLVMOp: "movshdup"},
	{Op: "VMOVSHDUP", Family: asm.FamilyVecShuffle, LaneBits: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "movshdup"},
	{Op: "MOVDDUP", Family: asm.FamilyVecShuffle, LaneBits: 64, Effect: asm.EffectWriteOnly, LLVMOp: "movddup"},
	{Op: "VMOVDDUP", Family: asm.FamilyVecShuffle, LaneBits: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "movddup"},
	{Op: "BLENDVPS", Family: asm.FamilyVecShuffle, LaneBits: 32, Effect: asm.EffectReadWrite, LLVMOp: "blendv"},
	{Op: "BLENDVPD", Family: asm.FamilyVecShuffle, LaneBits: 64, Effect: asm.EffectReadWrite, LLVMOp: "blendv"},
	{Op: "PBLENDVB", Family: asm.FamilyVecShuffle, LaneBits: 8, Effect: asm.EffectReadWrite, LLVMOp: "blendv"},
	{Op: "VBLENDVPS", Family: asm.FamilyVecShuffle, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "blendv"},
	{Op: "VBLENDVPD", Family: asm.FamilyVecShuffle, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "blendv"},
	{Op: "VPBLENDVB", Family: asm.FamilyVecShuffle, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "blendv"},
	{Op: "PACKSSWB", Family: asm.FamilyVecShuffle, SrcWidth: 16, LaneBits: 8, Signed: true, Effect: asm.EffectReadWrite, LLVMOp: "pack"},
	{Op: "PACKUSWB", Family: asm.FamilyVecShuffle, SrcWidth: 16, LaneBits: 8, Effect: asm.EffectReadWrite, LLVMOp: "pack"},
	{Op: "PACKSSLW", Family: asm.FamilyVecShuffle, SrcWidth: 32, LaneBits: 16, Signed: true, Effect: asm.EffectReadWrite, LLVMOp: "pack"},
	{Op: "PACKSSDW", Family: asm.FamilyVecShuffle, SrcWidth: 32, LaneBits: 16, Signed: true, Effect: asm.EffectReadWrite, LLVMOp: "pack"},
	{Op: "PACKUSDW", Family: asm.FamilyVecShuffle, SrcWidth: 32, LaneBits: 16, Effect: asm.EffectReadWrite, LLVMOp: "pack"},
	{Op: "VPACKSSWB", Family: asm.FamilyVecShuffle, SrcWidth: 16, LaneBits: 8, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "pack"},
	{Op: "VPACKUSWB", Family: asm.FamilyVecShuffle, SrcWidth: 16, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "pack"},
	{Op: "VPACKSSDW", Family: asm.FamilyVecShuffle, SrcWidth: 32, LaneBits: 16, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "pack"},
	{Op: "VPACKUSDW", Family: asm.FamilyVecShuffle, SrcWidth: 32, LaneBits: 16, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "pack"},
	{Op: "VALIGND", Family: asm.FamilyVecShuffle, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "valign"},
	{Op: "VALIGNQ", Family: asm.FamilyVecShuffle, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "valign"},
	{Op: "VPERMILPS", Family: asm.FamilyVecShuffle, LaneBits: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpermil"},
	{Op: "VPERMILPD", Family: asm.FamilyVecShuffle, LaneBits: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpermil"},
	{Op: "VPERMQ", Family: asm.FamilyVecShuffle, LaneBits: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpermq"},
	{Op: "VPERMPD", Family: asm.FamilyVecShuffle, LaneBits: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpermq"},

	// Lane extract & insert
	{Op: "VEXTRACTF128", Family: asm.FamilyVecShuffle, Width: 128, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vextract_sub"},
	{Op: "VEXTRACTI128", Family: asm.FamilyVecShuffle, Width: 128, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vextract_sub"},
	{Op: "VEXTRACTF32X8", Family: asm.FamilyVecShuffle, Width: 256, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vextract_sub"},
	{Op: "VEXTRACTF64X2", Family: asm.FamilyVecShuffle, Width: 128, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vextract_sub"},
	{Op: "VEXTRACTF64X4", Family: asm.FamilyVecShuffle, Width: 256, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vextract_sub"},
	{Op: "VEXTRACTI32X4", Family: asm.FamilyVecShuffle, Width: 128, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vextract_sub"},
	{Op: "VEXTRACTI32X8", Family: asm.FamilyVecShuffle, Width: 256, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vextract_sub"},
	{Op: "VEXTRACTI64X2", Family: asm.FamilyVecShuffle, Width: 128, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vextract_sub"},
	{Op: "VEXTRACTI64X4", Family: asm.FamilyVecShuffle, Width: 256, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vextract_sub"},
	{Op: "VINSERTF128", Family: asm.FamilyVecShuffle, Width: 128, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vinsert_sub"},
	{Op: "VINSERTF32X4", Family: asm.FamilyVecShuffle, Width: 128, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vinsert_sub"},
	{Op: "VINSERTF32X8", Family: asm.FamilyVecShuffle, Width: 256, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vinsert_sub"},
	{Op: "VINSERTF64X2", Family: asm.FamilyVecShuffle, Width: 128, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vinsert_sub"},
	{Op: "VINSERTF64X4", Family: asm.FamilyVecShuffle, Width: 256, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vinsert_sub"},
	{Op: "VINSERTI32X4", Family: asm.FamilyVecShuffle, Width: 128, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vinsert_sub"},
	{Op: "VINSERTI32X8", Family: asm.FamilyVecShuffle, Width: 256, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vinsert_sub"},
	{Op: "VINSERTI64X2", Family: asm.FamilyVecShuffle, Width: 128, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vinsert_sub"},
	{Op: "VINSERTI64X4", Family: asm.FamilyVecShuffle, Width: 256, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vinsert_sub"},
	{Op: "EXTRACTPS", Family: asm.FamilyVecShuffle, LaneBits: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpextr"},
	{Op: "VEXTRACTPS", Family: asm.FamilyVecShuffle, LaneBits: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpextr"},
	{Op: "PEXTRW", Family: asm.FamilyVecShuffle, LaneBits: 16, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpextr"},
	{Op: "VPEXTRB", Family: asm.FamilyVecShuffle, LaneBits: 8, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpextr"},
	{Op: "VPEXTRW", Family: asm.FamilyVecShuffle, LaneBits: 16, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpextr"},
	{Op: "VPEXTRD", Family: asm.FamilyVecShuffle, LaneBits: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpextr"},
	{Op: "VPEXTRQ", Family: asm.FamilyVecShuffle, LaneBits: 64, Effect: asm.EffectWriteOnly, LLVMOp: "vpextr"},
	{Op: "VPINSRB", Family: asm.FamilyVecShuffle, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpinsr"},
	{Op: "VPINSRW", Family: asm.FamilyVecShuffle, LaneBits: 16, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpinsr"},
	{Op: "VPINSRD", Family: asm.FamilyVecShuffle, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpinsr"},
	{Op: "VPINSRQ", Family: asm.FamilyVecShuffle, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vpinsr"},
	{Op: "INSERTPS", Family: asm.FamilyVecShuffle, LaneBits: 32, Effect: asm.EffectReadWrite, LLVMOp: "insertps"},
	{Op: "VINSERTPS", Family: asm.FamilyVecShuffle, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "insertps"},

	// Packed shifts (missing widths, reg-counts, V* & variable per-lane shifts)
	{Op: "PSLLW", Family: asm.FamilyVecShift, LaneBits: 16, Effect: asm.EffectReadWrite, LLVMOp: "shl"},
	{Op: "PSRLW", Family: asm.FamilyVecShift, LaneBits: 16, Effect: asm.EffectReadWrite, LLVMOp: "lshr"},
	{Op: "PSLLL", Family: asm.FamilyVecShift, LaneBits: 32, Effect: asm.EffectReadWrite, LLVMOp: "shl"},
	{Op: "PSRLL", Family: asm.FamilyVecShift, LaneBits: 32, Effect: asm.EffectReadWrite, LLVMOp: "lshr"},
	{Op: "PSRAL", Family: asm.FamilyVecShift, LaneBits: 32, Signed: true, Effect: asm.EffectReadWrite, LLVMOp: "ashr"},
	{Op: "PSLLQ", Family: asm.FamilyVecShift, LaneBits: 64, Effect: asm.EffectReadWrite, LLVMOp: "shl"},
	{Op: "PSRLQ", Family: asm.FamilyVecShift, LaneBits: 64, Effect: asm.EffectReadWrite, LLVMOp: "lshr"},
	{Op: "PSLLO", Family: asm.FamilyVecShift, LaneBits: 128, Effect: asm.EffectReadWrite, LLVMOp: "shl_byte"},
	{Op: "PSRLO", Family: asm.FamilyVecShift, LaneBits: 128, Effect: asm.EffectReadWrite, LLVMOp: "lshr_byte"},
	{Op: "PSRAW", Family: asm.FamilyVecShift, LaneBits: 16, Signed: true, Effect: asm.EffectReadWrite, LLVMOp: "ashr"},
	{Op: "VPSLLW", Family: asm.FamilyVecShift, LaneBits: 16, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "shl"},
	{Op: "VPSRLW", Family: asm.FamilyVecShift, LaneBits: 16, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "lshr"},
	{Op: "VPSRAW", Family: asm.FamilyVecShift, LaneBits: 16, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "ashr"},
	{Op: "VPSLLD", Family: asm.FamilyVecShift, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "shl"},
	{Op: "VPSRLD", Family: asm.FamilyVecShift, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "lshr"},
	{Op: "VPSRAD", Family: asm.FamilyVecShift, LaneBits: 32, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "ashr"},
	{Op: "VPSLLQ", Family: asm.FamilyVecShift, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "shl"},
	{Op: "VPSRLQ", Family: asm.FamilyVecShift, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "lshr"},
	{Op: "VPSRAQ", Family: asm.FamilyVecShift, LaneBits: 64, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "ashr"},
	{Op: "VPSLLDQ", Family: asm.FamilyVecShift, LaneBits: 128, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "shl_byte"},
	{Op: "VPSRLDQ", Family: asm.FamilyVecShift, LaneBits: 128, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "lshr_byte"},
	{Op: "VPSLLVW", Family: asm.FamilyVecShift, LaneBits: 16, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vshl_var"},
	{Op: "VPSLLVD", Family: asm.FamilyVecShift, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vshl_var"},
	{Op: "VPSLLVQ", Family: asm.FamilyVecShift, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vshl_var"},
	{Op: "VPSRLVW", Family: asm.FamilyVecShift, LaneBits: 16, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vlshr_var"},
	{Op: "VPSRLVD", Family: asm.FamilyVecShift, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vlshr_var"},
	{Op: "VPSRLVQ", Family: asm.FamilyVecShift, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vlshr_var"},
	{Op: "VPSRAVW", Family: asm.FamilyVecShift, LaneBits: 16, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vashr_var"},
	{Op: "VPSRAVD", Family: asm.FamilyVecShift, LaneBits: 32, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vashr_var"},
	{Op: "VPSRAVQ", Family: asm.FamilyVecShift, LaneBits: 64, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vashr_var"},
	{Op: "VPRORD", Family: asm.FamilyVecShift, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vror"},
	{Op: "VPRORQ", Family: asm.FamilyVecShift, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vror"},
	{Op: "VPROLD", Family: asm.FamilyVecShift, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vrol"},
	{Op: "VPROLQ", Family: asm.FamilyVecShift, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "vrol"},

	// VEX AES, PCLMUL, dot-product, SAD, minpos, string compare, gather/scatter prefetches
	{Op: "PCLMULQDQ", Family: asm.FamilyVecShuffle, LaneBits: 64, Effect: asm.EffectReadWrite, LLVMOp: "pclmul"},
	{Op: "VPCLMULQDQ", Family: asm.FamilyVecShuffle, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "pclmul"},
	{Op: "PCMPESTRI", Family: asm.FamilyVecShuffle, Effect: asm.EffectImplicit, Flags: asm.FlagsWrite, LLVMOp: "pcmpstr"},
	{Op: "VAESENC", Family: asm.FamilyCrypto, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "aesenc", ArchFeature: "+aes,+avx"},
	{Op: "VAESENCLAST", Family: asm.FamilyCrypto, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "aesenclast", ArchFeature: "+aes,+avx"},
	{Op: "VAESDEC", Family: asm.FamilyCrypto, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "aesdec", ArchFeature: "+aes,+avx"},
	{Op: "VAESDECLAST", Family: asm.FamilyCrypto, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "aesdeclast", ArchFeature: "+aes,+avx"},
	{Op: "VAESIMC", Family: asm.FamilyCrypto, Effect: asm.EffectWriteZeroUpper, LLVMOp: "aesimc", ArchFeature: "+aes,+avx"},
	{Op: "VAESKEYGENASSIST", Family: asm.FamilyCrypto, Effect: asm.EffectWriteZeroUpper, LLVMOp: "aeskeygenassist", ArchFeature: "+aes,+avx"},
	{Op: "DPPS", Family: asm.FamilyVecShuffle, LaneBits: 32, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "dp"},
	{Op: "DPPD", Family: asm.FamilyVecShuffle, LaneBits: 64, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "dp"},
	{Op: "VDPPS", Family: asm.FamilyVecShuffle, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "dp"},
	{Op: "VDPPD", Family: asm.FamilyVecShuffle, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "dp"},
	{Op: "PSADBW", Family: asm.FamilyVecShuffle, LaneBits: 8, Effect: asm.EffectReadWrite, LLVMOp: "psadbw"},
	{Op: "VPSADBW", Family: asm.FamilyVecShuffle, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "psadbw"},
	{Op: "PHMINPOSUW", Family: asm.FamilyVecShuffle, LaneBits: 16, Effect: asm.EffectWriteOnly, LLVMOp: "phminposuw"},
	{Op: "VPHMINPOSUW", Family: asm.FamilyVecShuffle, LaneBits: 16, Effect: asm.EffectWriteZeroUpper, LLVMOp: "phminposuw"},
	{Op: "PCMPESTRM", Family: asm.FamilyVecShuffle, Effect: asm.EffectImplicit, Flags: asm.FlagsWrite, LLVMOp: "pcmpstr"},
	{Op: "PCMPISTRI", Family: asm.FamilyVecShuffle, Effect: asm.EffectImplicit, Flags: asm.FlagsWrite, LLVMOp: "pcmpstr"},
	{Op: "PCMPISTRM", Family: asm.FamilyVecShuffle, Effect: asm.EffectImplicit, Flags: asm.FlagsWrite, LLVMOp: "pcmpstr"},
	{Op: "VPCMPESTRI", Family: asm.FamilyVecShuffle, Effect: asm.EffectImplicit, Flags: asm.FlagsWrite, LLVMOp: "pcmpstr"},
	{Op: "VPCMPESTRM", Family: asm.FamilyVecShuffle, Effect: asm.EffectImplicit, Flags: asm.FlagsWrite, LLVMOp: "pcmpstr"},
	{Op: "VPCMPISTRI", Family: asm.FamilyVecShuffle, Effect: asm.EffectImplicit, Flags: asm.FlagsWrite, LLVMOp: "pcmpstr"},
	{Op: "VPCMPISTRM", Family: asm.FamilyVecShuffle, Effect: asm.EffectImplicit, Flags: asm.FlagsWrite, LLVMOp: "pcmpstr"},
	{Op: "VGATHERPF0DPD", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "prefetch_gs"},
	{Op: "VGATHERPF0DPS", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "prefetch_gs"},
	{Op: "VGATHERPF0QPD", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "prefetch_gs"},
	{Op: "VGATHERPF0QPS", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "prefetch_gs"},
	{Op: "VGATHERPF1DPD", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "prefetch_gs"},
	{Op: "VGATHERPF1DPS", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "prefetch_gs"},
	{Op: "VGATHERPF1QPD", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "prefetch_gs"},
	{Op: "VGATHERPF1QPS", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "prefetch_gs"},
	{Op: "VSCATTERPF0DPD", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "prefetch_gs"},
	{Op: "VSCATTERPF0DPS", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "prefetch_gs"},
	{Op: "VSCATTERPF0QPD", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "prefetch_gs"},
	{Op: "VSCATTERPF0QPS", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "prefetch_gs"},
	{Op: "VSCATTERPF1DPD", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "prefetch_gs"},
	{Op: "VSCATTERPF1DPS", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "prefetch_gs"},
	{Op: "VSCATTERPF1QPD", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "prefetch_gs"},
	{Op: "VSCATTERPF1QPS", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "prefetch_gs"},
}

var x86ExtraSIMDTable = asm.NewOpTable(x86ExtraSIMDSpecs)

type x86VecInfo struct {
	totalBits int
	byteVecTy string
	loadVec   func(asm.Operand) (string, error)
	loadReg   func(asm.Reg) (string, error)
	storeVec  func(asm.Reg, string) error
}

func amd64ParseMReg(r asm.Reg) (int, bool) {
	s := strings.ToUpper(strings.TrimSpace(string(r)))
	if len(s) == 2 && s[0] == 'M' && s[1] >= '0' && s[1] <= '7' {
		return int(s[1] - '0'), true
	}
	return 0, false
}

func isAMD64MReg(r asm.Reg) bool { _, ok := amd64ParseMReg(r); return ok }

func (c *amd64Ctx) loadM(r asm.Reg) (string, error) {
	if _, ok := amd64ParseMReg(r); !ok {
		return "", fmt.Errorf("not an M reg: %s", r)
	}
	v64, err := c.loadReg(r)
	if err != nil {
		return "", err
	}
	bc := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to <8 x i8>\n", bc, v64)
	return "%" + bc, nil
}

func (c *amd64Ctx) storeM(r asm.Reg, v string) error {
	if _, ok := amd64ParseMReg(r); !ok {
		return fmt.Errorf("not an M reg: %s", r)
	}
	bc := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <8 x i8> %s to i64\n", bc, v)
	return c.storeReg(r, "%"+bc)
}

func (c *amd64Ctx) loadMVecOperand(op asm.Operand) (string, error) {
	switch op.Kind {
	case asm.OpReg:
		return c.loadM(op.Reg)
	case asm.OpMem:
		p, ptrType, err := c.ptrFromMem(op.Mem)
		if err != nil {
			return "", err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load <8 x i8>, %s %s, align 1\n", t, ptrType, p)
		return "%" + t, nil
	case asm.OpSym:
		p, err := c.ptrFromSB(op.Sym)
		if err != nil {
			return "", err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load <8 x i8>, ptr %s, align 1\n", t, p)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("amd64: unsupported M-vector operand %s", op.String())
	}
}

func (c *amd64Ctx) x86VecInfoForReg(r asm.Reg) (x86VecInfo, bool) {
	switch {
	case isAMD64MReg(r):
		return x86VecInfo{64, "<8 x i8>", c.loadMVecOperand, c.loadM, c.storeM}, true
	case isAMD64XReg(r):
		return x86VecInfo{128, "<16 x i8>", c.loadXVecOperand, c.loadX, c.storeX}, true
	case isAMD64YReg(r):
		return x86VecInfo{256, "<32 x i8>", c.loadYVecOperand, c.loadY, c.storeY}, true
	case isAMD64ZReg(r):
		return x86VecInfo{512, "<64 x i8>", c.loadZVecOperand, c.loadZ, c.storeZ}, true
	default:
		return x86VecInfo{}, false
	}
}

func isAMD64KReg(r asm.Reg) bool { _, ok := amd64ParseKReg(r); return ok }

// x86StripEVEXMask extracts an optional EVEX writemask register `K1..K7`
// positioned immediately before the final destination operand (Plan 9 syntax:
// `OP src1, [src2,] Kmask, dst`), returning the stripped arg slice and mask reg.
func x86StripEVEXMask(args []asm.Operand) (stripped []asm.Operand, kreg asm.Reg, hasMask bool) {
	if len(args) >= 3 {
		cand := args[len(args)-2]
		if cand.Kind == asm.OpReg && isAMD64KReg(cand.Reg) {
			out := make([]asm.Operand, 0, len(args)-1)
			out = append(out, args[:len(args)-2]...)
			out = append(out, args[len(args)-1])
			return out, cand.Reg, true
		}
	}
	return args, "", false
}

// x86ApplyMask blends `resVal` with `oldVal` (or zeroinitializer when zeroMask)
// lane-by-lane according to the low `lanes` bits of `kreg`.
func (c *amd64Ctx) x86ApplyMask(kreg asm.Reg, zeroMask bool, lanes int, vecTy, resVal, oldVal string) (string, error) {
	kv, err := c.loadK(kreg)
	if err != nil {
		return "", err
	}
	var maskBits string
	if lanes == 64 {
		maskBits = kv
	} else {
		tr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", tr, kv, lanes)
		maskBits = "%" + tr
	}
	mvec := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast i%d %s to <%d x i1>\n", mvec, lanes, maskBits, lanes)
	fb := oldVal
	if zeroMask {
		fb = "zeroinitializer"
	}
	sel := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %s\n", sel, lanes, mvec, vecTy, resVal, vecTy, fb)
	return "%" + sel, nil
}

func (c *amd64Ctx) loadXLowF32(r asm.Reg) (string, error) {
	v, err := c.loadX(r)
	if err != nil {
		return "", err
	}
	bc, el := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x float>\n", bc, v)
	fmt.Fprintf(c.b, "  %%%s = extractelement <4 x float> %%%s, i32 0\n", el, bc)
	return "%" + el, nil
}

func (c *amd64Ctx) storeXLowF32(r asm.Reg, val string) error {
	v, err := c.loadX(r)
	if err != nil {
		return err
	}
	bc, ins, out := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x float>\n", bc, v)
	fmt.Fprintf(c.b, "  %%%s = insertelement <4 x float> %%%s, float %s, i32 0\n", ins, bc, val)
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x float> %%%s to <16 x i8>\n", out, ins)
	return c.storeX(r, "%"+out)
}

func (c *amd64Ctx) evalF32(op asm.Operand) (string, error) {
	switch op.Kind {
	case asm.OpReg:
		return c.loadXLowF32(op.Reg)
	case asm.OpMem:
		p, ptrType, err := c.ptrFromMem(op.Mem)
		if err != nil {
			return "", err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load float, %s %s, align 1\n", t, ptrType, p)
		return "%" + t, nil
	case asm.OpSym:
		p, err := c.ptrFromSB(op.Sym)
		if err != nil {
			return "", err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load float, ptr %s, align 1\n", t, p)
		return "%" + t, nil
	case asm.OpFP:
		v64, err := c.evalFPToF64(op.FPOffset)
		if err != nil {
			return "", err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fptrunc double %s to float\n", t, v64)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("amd64: unsupported f32 operand %s", op.String())
	}
}

func (c *amd64Ctx) lowerSIMDDeclarative(op asm.Op, ins asm.Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(ins.Op))
	zeroMask := strings.Contains(rawOp, ".Z")
	baseOp := op
	if dot := strings.IndexByte(string(baseOp), '.'); dot >= 0 {
		baseOp = asm.Op(string(baseOp)[:dot])
	}
	spec, found := x86ExtraSIMDTable.Lookup(baseOp)
	if !found {
		return false, false, nil
	}
	switch spec.Family {
	case asm.FamilyMask:
		return true, false, c.lowerX86KMask(spec, ins)
	case asm.FamilyFP:
		return true, false, c.lowerX86ScalarFPDeclarative(spec, zeroMask, ins)
	case asm.FamilyVecUnary:
		return true, false, c.lowerX86VecUnaryDeclarative(spec, zeroMask, ins)
	case asm.FamilyMove:
		return true, false, c.lowerX86VecMoveDeclarative(spec, zeroMask, ins)
	case asm.FamilyVecShift:
		return true, false, c.lowerX86VecShiftDeclarative(spec, zeroMask, ins)
	case asm.FamilyVecShuffle:
		return true, false, c.lowerX86VecShuffleDeclarative(spec, zeroMask, ins)
	case asm.FamilyCrypto:
		return true, false, c.lowerX86VAESDeclarative(spec, zeroMask, ins)
	case asm.FamilySystem:
		if spec.LLVMOp == "prefetch_gs" {
			return true, false, nil
		}
	}
	return false, false, nil
}

func (c *amd64Ctx) lowerX86KMask(spec asm.OpSpec, ins asm.Instr) error {
	ty := x86LLVMIntType(spec.Width)
	switch spec.LLVMOp {
	case "mov":
		if len(ins.Args) != 2 {
			return fmt.Errorf("amd64 %s expects 2 operands: %q", spec.Op, ins.Raw)
		}
		var v64 string
		var err error
		if ins.Args[0].Kind == asm.OpReg && isAMD64KReg(ins.Args[0].Reg) {
			v64, err = c.loadK(ins.Args[0].Reg)
		} else {
			v, e := c.evalIntSized(ins.Args[0], ty)
			if e != nil {
				return e
			}
			z := c.newTmp()
			if ty == asm.I64 {
				v64 = v
			} else {
				fmt.Fprintf(c.b, "  %%%s = zext %s %s to i64\n", z, ty, v)
				v64 = "%" + z
			}
		}
		if err != nil {
			return err
		}
		if ins.Args[1].Kind == asm.OpReg && isAMD64KReg(ins.Args[1].Reg) {
			return c.storeK(ins.Args[1].Reg, v64)
		}
		if ins.Args[1].Kind == asm.OpReg {
			tr := v64
			if ty != asm.I64 {
				t := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", t, v64, ty)
				tr = "%" + t
			}
			return c.storeRegSized(ins.Args[1].Reg, ty, tr)
		}
		if ins.Args[1].Kind == asm.OpMem {
			p, ptrType, err := c.ptrFromMem(ins.Args[1].Mem)
			if err != nil {
				return err
			}
			tr := v64
			if ty != asm.I64 {
				t := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", t, v64, ty)
				tr = "%" + t
			}
			fmt.Fprintf(c.b, "  store %s %s, %s %s, align 1\n", ty, tr, ptrType, p)
			return nil
		}
		return fmt.Errorf("amd64 %s unsupported dst: %q", spec.Op, ins.Raw)

	case "not":
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects Ksrc, Kdst: %q", spec.Op, ins.Raw)
		}
		src, err := c.loadK(ins.Args[0].Reg)
		if err != nil {
			return err
		}
		res := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i64 %s, -1\n", res, src)
		out := "%" + res
		if spec.Width < 64 {
			m := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, %d\n", m, res, (uint64(1)<<spec.Width)-1)
			out = "%" + m
		}
		return c.storeK(ins.Args[1].Reg, out)

	case "shl", "lshr":
		if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpImm || ins.Args[1].Kind != asm.OpReg || ins.Args[2].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects $imm, Ksrc, Kdst: %q", spec.Op, ins.Raw)
		}
		src, err := c.loadK(ins.Args[1].Reg)
		if err != nil {
			return err
		}
		amt := ins.Args[0].Imm & 63
		var out string
		if uint16(amt) >= spec.Width {
			out = "0"
		} else {
			sv := src
			if spec.Width < 64 {
				t := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", t, src, ty)
				sv = "%" + t
			}
			sh := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = %s %s %s, %d\n", sh, spec.LLVMOp, ty, sv, amt)
			out = "%" + sh
			if spec.Width < 64 {
				z := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = zext %s %%%s to i64\n", z, ty, sh)
				out = "%" + z
			}
		}
		return c.storeK(ins.Args[2].Reg, out)

	default:
		if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg || ins.Args[2].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects K1, K2, Kdst: %q", spec.Op, ins.Raw)
		}
		a, err := c.loadK(ins.Args[0].Reg)
		if err != nil {
			return err
		}
		b, err := c.loadK(ins.Args[1].Reg)
		if err != nil {
			return err
		}
		var res string
		switch spec.LLVMOp {
		case "add", "and", "or", "xor":
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = %s i64 %s, %s\n", t, spec.LLVMOp, b, a)
			res = "%" + t
		case "andn":
			inv, t := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i64 %s, -1\n", inv, b)
			fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, %s\n", t, inv, a)
			res = "%" + t
		case "xnor":
			x, t := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i64 %s, %s\n", x, b, a)
			fmt.Fprintf(c.b, "  %%%s = xor i64 %%%s, -1\n", t, x)
			res = "%" + t
		}
		if spec.Width < 64 {
			m := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i64 %s, %d\n", m, res, (uint64(1)<<spec.Width)-1)
			res = "%" + m
		}
		return c.storeK(ins.Args[2].Reg, res)
	}
}

func (c *amd64Ctx) lowerX86ScalarFPDeclarative(spec asm.OpSpec, zeroMask bool, ins asm.Instr) error {
	args, kreg, hasMask := x86StripEVEXMask(ins.Args)
	ty, suf := "float", "f32"
	if spec.Width == 64 {
		ty, suf = "double", "f64"
	}
	evalS := func(o asm.Operand) (string, error) {
		if spec.Width == 64 {
			return c.evalF64(o)
		}
		return c.evalF32(o)
	}
	storeS := func(r asm.Reg, val string) error {
		if hasMask {
			kv, err := c.loadK(kreg)
			if err != nil {
				return err
			}
			bit := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i1\n", bit, kv)
			fb := "0.0"
			if !zeroMask {
				fb, err = evalS(asm.Operand{Kind: asm.OpReg, Reg: r})
				if err != nil {
					return err
				}
			}
			sel := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %s, %s %s\n", sel, bit, ty, val, ty, fb)
			val = "%" + sel
		}
		if spec.Width == 64 {
			return c.storeXLowF64(r, val)
		}
		return c.storeXLowF32(r, val)
	}

	switch spec.LLVMOp {
	case "movs":
		if len(args) == 3 && args[2].Kind == asm.OpReg {
			// VMOVSS/VMOVSD Xa, Xb, Xd => low lane from Xa, upper lanes from Xb
			lo, err := evalS(args[0])
			if err != nil {
				return err
			}
			upper, err := c.loadXVecOperand(args[1])
			if err != nil {
				return err
			}
			if err := c.storeX(args[2].Reg, upper); err != nil {
				return err
			}
			return storeS(args[2].Reg, lo)
		}
		if len(args) != 2 {
			return fmt.Errorf("amd64 %s expects 2 or 3 operands: %q", spec.Op, ins.Raw)
		}
		v, err := evalS(args[0])
		if err != nil {
			return err
		}
		switch args[1].Kind {
		case asm.OpReg:
			if args[0].Kind != asm.OpReg {
				// Load from mem/FP/SB into X reg zeroes upper lanes.
				if err := c.storeX(args[1].Reg, "zeroinitializer"); err != nil {
					return err
				}
			}
			return storeS(args[1].Reg, v)
		case asm.OpMem:
			p, ptrType, err := c.ptrFromMem(args[1].Mem)
			if err != nil {
				return err
			}
			fmt.Fprintf(c.b, "  store %s %s, %s %s, align 1\n", ty, v, ptrType, p)
			return nil
		case asm.OpSym:
			p, err := c.ptrFromSB(args[1].Sym)
			if err != nil {
				return err
			}
			fmt.Fprintf(c.b, "  store %s %s, ptr %s, align 1\n", ty, v, p)
			return nil
		case asm.OpFP:
			return c.storeFPResult(args[1].FPOffset, asm.LLVMType(ty), v)
		default:
			return fmt.Errorf("amd64 %s unsupported dst: %q", spec.Op, ins.Raw)
		}

	case "fadd", "fsub", "fmul", "fdiv", "fmin", "fmax":
		var rhsOp, lhsOp, dstOp asm.Operand
		if spec.ThreeOp {
			if len(args) != 3 || args[2].Kind != asm.OpReg {
				return fmt.Errorf("amd64 %s expects 3 operands: %q", spec.Op, ins.Raw)
			}
			rhsOp, lhsOp, dstOp = args[0], args[1], args[2]
		} else {
			if len(args) != 2 || args[1].Kind != asm.OpReg {
				return fmt.Errorf("amd64 %s expects 2 operands: %q", spec.Op, ins.Raw)
			}
			rhsOp, lhsOp, dstOp = args[0], args[1], args[1]
		}
		rhs, err := evalS(rhsOp)
		if err != nil {
			return err
		}
		lhs, err := evalS(lhsOp)
		if err != nil {
			return err
		}
		if spec.ThreeOp && lhsOp.Kind == asm.OpReg && lhsOp.Reg != dstOp.Reg {
			if upper, e := c.loadX(lhsOp.Reg); e == nil {
				_ = c.storeX(dstOp.Reg, upper)
			}
		}
		out := c.newTmp()
		switch spec.LLVMOp {
		case "fmin":
			cmp := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fcmp olt %s %s, %s\n", cmp, ty, lhs, rhs)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %s, %s %s\n", out, cmp, ty, lhs, ty, rhs)
		case "fmax":
			cmp := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fcmp ogt %s %s, %s\n", cmp, ty, lhs, rhs)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %s, %s %s\n", out, cmp, ty, lhs, ty, rhs)
		default:
			fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", out, spec.LLVMOp, ty, lhs, rhs)
		}
		return storeS(dstOp.Reg, "%"+out)

	case "sqrt", "rcp", "rsqrt":
		var srcOp, dstOp asm.Operand
		if spec.ThreeOp && len(args) == 3 {
			srcOp, dstOp = args[0], args[2]
			if upper, e := c.loadXVecOperand(args[1]); e == nil {
				_ = c.storeX(dstOp.Reg, upper)
			}
		} else if len(args) == 2 {
			srcOp, dstOp = args[0], args[1]
		} else {
			return fmt.Errorf("amd64 %s unexpected operand count: %q", spec.Op, ins.Raw)
		}
		if dstOp.Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s dst must be Xreg: %q", spec.Op, ins.Raw)
		}
		src, err := evalS(srcOp)
		if err != nil {
			return err
		}
		out := c.newTmp()
		switch spec.LLVMOp {
		case "sqrt":
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.sqrt.%s(%s %s)\n", out, ty, suf, ty, src)
		case "rcp":
			fmt.Fprintf(c.b, "  %%%s = fdiv %s 1.0, %s\n", out, ty, src)
		case "rsqrt":
			sq := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.sqrt.%s(%s %s)\n", sq, ty, suf, ty, src)
			fmt.Fprintf(c.b, "  %%%s = fdiv %s 1.0, %%%s\n", out, ty, sq)
		}
		return storeS(dstOp.Reg, "%"+out)

	case "comi":
		if len(args) != 2 {
			return fmt.Errorf("amd64 %s expects 2 operands: %q", spec.Op, ins.Raw)
		}
		src, err := evalS(args[0])
		if err != nil {
			return err
		}
		dst, err := evalS(args[1])
		if err != nil {
			return err
		}
		z, cf, lt := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fcmp ueq %s %s, %s\n", z, ty, dst, src)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", z, c.flagsZSlot)
		fmt.Fprintf(c.b, "  %%%s = fcmp ult %s %s, %s\n", cf, ty, dst, src)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
		fmt.Fprintf(c.b, "  %%%s = fcmp olt %s %s, %s\n", lt, ty, dst, src)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", lt, c.flagsSltSlot)
		return nil

	case "i2f":
		var srcOp, dstOp asm.Operand
		if spec.ThreeOp && len(args) == 3 {
			srcOp, dstOp = args[0], args[2]
			if upper, e := c.loadXVecOperand(args[1]); e == nil {
				_ = c.storeX(dstOp.Reg, upper)
			}
		} else if len(args) == 2 {
			srcOp, dstOp = args[0], args[1]
		} else {
			return fmt.Errorf("amd64 %s unexpected operand count: %q", spec.Op, ins.Raw)
		}
		if dstOp.Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s dst must be Xreg: %q", spec.Op, ins.Raw)
		}
		srcTy := x86LLVMIntType(spec.SrcWidth)
		iv, err := c.evalIntSized(srcOp, srcTy)
		if err != nil {
			return err
		}
		fv := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sitofp %s %s to %s\n", fv, srcTy, iv, ty)
		return storeS(dstOp.Reg, "%"+fv)

	case "f2f":
		var srcOp, dstOp asm.Operand
		if spec.ThreeOp && len(args) == 3 {
			srcOp, dstOp = args[0], args[2]
			if upper, e := c.loadXVecOperand(args[1]); e == nil {
				_ = c.storeX(dstOp.Reg, upper)
			}
		} else if len(args) == 2 {
			srcOp, dstOp = args[0], args[1]
		} else {
			return fmt.Errorf("amd64 %s unexpected operand count: %q", spec.Op, ins.Raw)
		}
		if dstOp.Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s dst must be Xreg: %q", spec.Op, ins.Raw)
		}
		var sv string
		var err error
		if spec.SrcWidth == 32 {
			sv, err = c.evalF32(srcOp)
		} else {
			sv, err = c.evalF64(srcOp)
		}
		if err != nil {
			return err
		}
		out := c.newTmp()
		if spec.Width == 64 {
			fmt.Fprintf(c.b, "  %%%s = fpext float %s to double\n", out, sv)
		} else {
			fmt.Fprintf(c.b, "  %%%s = fptrunc double %s to float\n", out, sv)
		}
		return storeS(dstOp.Reg, "%"+out)

	case "f2i":
		if len(args) != 2 || args[1].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects src, dstReg: %q", spec.Op, ins.Raw)
		}
		var sv string
		var err error
		srcTy := "double"
		if spec.SrcWidth == 32 {
			srcTy = "float"
			sv, err = c.evalF32(args[0])
		} else {
			sv, err = c.evalF64(args[0])
		}
		if err != nil {
			return err
		}
		dstTy := x86LLVMIntType(spec.Width)
		iv := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fptosi %s %s to %s\n", iv, srcTy, sv, dstTy)
		return c.storeRegSized(args[1].Reg, dstTy, "%"+iv)
	}
	return fmt.Errorf("amd64: unhandled scalar FP %s", spec.Op)
}

func (c *amd64Ctx) lowerX86VecUnaryDeclarative(spec asm.OpSpec, zeroMask bool, ins asm.Instr) error {
	args, kreg, hasMask := x86StripEVEXMask(ins.Args)
	if len(args) != 2 || args[1].Kind != asm.OpReg {
		return fmt.Errorf("amd64 %s expects src, Vdst: %q", spec.Op, ins.Raw)
	}
	vi, ok := c.x86VecInfoForReg(args[1].Reg)
	if !ok {
		return fmt.Errorf("amd64 %s requires vector dst: %q", spec.Op, ins.Raw)
	}
	laneBits := int(spec.LaneBits)
	lanes := vi.totalBits / laneBits
	elemTy := fmt.Sprintf("i%d", laneBits)
	if spec.Float {
		if laneBits == 32 {
			elemTy = "float"
		} else {
			elemTy = "double"
		}
	}
	vecTy := fmt.Sprintf("<%d x %s>", lanes, elemTy)

	if spec.LLVMOp == "vext" {
		// PMOVSX*/PMOVZX*: read low `lanes` elements of `SrcWidth` bits and extend to `LaneBits`.
		srcBits := int(spec.SrcWidth)
		srcBytes := (lanes * srcBits) / 8
		srcVecTy := fmt.Sprintf("<%d x i%d>", lanes, srcBits)
		var srcVal string
		if args[0].Kind == asm.OpReg {
			// Always read from the low bytes of an X/Y/Z register.
			sv, err := c.loadXVecOperand(args[0])
			if err != nil {
				if isAMD64YReg(args[0].Reg) {
					sv, err = c.loadY(args[0].Reg)
				} else if isAMD64ZReg(args[0].Reg) {
					sv, err = c.loadZ(args[0].Reg)
				}
			}
			if err != nil {
				return err
			}
			regBytes := 16
			if isAMD64YReg(args[0].Reg) {
				regBytes = 32
			} else if isAMD64ZReg(args[0].Reg) {
				regBytes = 64
			}
			mask := make([]string, srcBytes)
			for i := 0; i < srcBytes; i++ {
				mask[i] = fmt.Sprintf("i32 %d", i)
			}
			sub, bc := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i8> %s, <%d x i8> poison, <%d x i32> <%s>\n", sub, regBytes, sv, regBytes, srcBytes, strings.Join(mask, ", "))
			fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %%%s to %s\n", bc, srcBytes, sub, srcVecTy)
			srcVal = "%" + bc
		} else if args[0].Kind == asm.OpMem {
			p, ptrType, err := c.ptrFromMem(args[0].Mem)
			if err != nil {
				return err
			}
			ld := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load %s, %s %s, align 1\n", ld, srcVecTy, ptrType, p)
			srcVal = "%" + ld
		} else {
			return fmt.Errorf("amd64 %s unsupported src: %q", spec.Op, ins.Raw)
		}
		extOp := "zext"
		if spec.Signed {
			extOp = "sext"
		}
		ext := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", ext, extOp, srcVecTy, srcVal, vecTy)
		res := "%" + ext
		if hasMask {
			oldRaw, err := vi.loadReg(args[1].Reg)
			if err != nil {
				return err
			}
			oldV := oldRaw
			if vecTy != vi.byteVecTy {
				obc := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", obc, vi.byteVecTy, oldRaw, vecTy)
				oldV = "%" + obc
			}
			res, err = c.x86ApplyMask(kreg, zeroMask, lanes, vecTy, res, oldV)
			if err != nil {
				return err
			}
		}
		if vecTy != vi.byteVecTy {
			bc := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bc, vecTy, res, vi.byteVecTy)
			res = "%" + bc
		}
		return vi.storeVec(args[1].Reg, res)
	}

	rawSrc, err := vi.loadVec(args[0])
	if err != nil {
		return err
	}
	srcV := rawSrc
	if vecTy != vi.byteVecTy {
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bc, vi.byteVecTy, rawSrc, vecTy)
		srcV = "%" + bc
	}
	var res string
	switch spec.LLVMOp {
	case "abs":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.abs.v%di%d(%s %s, i1 false)\n", t, vecTy, lanes, laneBits, vecTy, srcV)
		res = "%" + t
	case "ctpop":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.ctpop.v%di%d(%s %s)\n", t, vecTy, lanes, laneBits, vecTy, srcV)
		res = "%" + t
	case "sqrt":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.sqrt.v%df%d(%s %s)\n", t, vecTy, lanes, laneBits, vecTy, srcV)
		res = "%" + t
	case "rcp":
		ones := x86FloatSplat(lanes, elemTy, "1.0")
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fdiv %s %s, %s\n", t, vecTy, ones, srcV)
		res = "%" + t
	case "rsqrt":
		ones := x86FloatSplat(lanes, elemTy, "1.0")
		sq, t := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.sqrt.v%df%d(%s %s)\n", sq, vecTy, lanes, laneBits, vecTy, srcV)
		fmt.Fprintf(c.b, "  %%%s = fdiv %s %s, %%%s\n", t, vecTy, ones, sq)
		res = "%" + t
	default:
		return fmt.Errorf("amd64: unhandled vec unary %s", spec.Op)
	}
	if hasMask {
		oldRaw, err := vi.loadReg(args[1].Reg)
		if err != nil {
			return err
		}
		oldV := oldRaw
		if vecTy != vi.byteVecTy {
			obc := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", obc, vi.byteVecTy, oldRaw, vecTy)
			oldV = "%" + obc
		}
		res, err = c.x86ApplyMask(kreg, zeroMask, lanes, vecTy, res, oldV)
		if err != nil {
			return err
		}
	}
	if vecTy != vi.byteVecTy {
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bc, vecTy, res, vi.byteVecTy)
		res = "%" + bc
	}
	return vi.storeVec(args[1].Reg, res)
}

func x86FloatSplat(lanes int, elemTy, lit string) string {
	elems := make([]string, lanes)
	for i := range elems {
		elems[i] = elemTy + " " + lit
	}
	return "<" + strings.Join(elems, ", ") + ">"
}

func (c *amd64Ctx) lowerX86VecMoveDeclarative(spec asm.OpSpec, zeroMask bool, ins asm.Instr) error {
	args, kreg, hasMask := x86StripEVEXMask(ins.Args)
	if len(args) != 2 {
		return fmt.Errorf("amd64 %s expects 2 operands: %q", spec.Op, ins.Raw)
	}
	laneBits := int(spec.LaneBits)
	if laneBits == 0 {
		laneBits = 32
		if strings.HasSuffix(string(spec.Op), "PD") || strings.HasSuffix(string(spec.Op), "64") {
			laneBits = 64
		}
	}
	if args[1].Kind == asm.OpReg {
		vi, ok := c.x86VecInfoForReg(args[1].Reg)
		if !ok {
			return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
		}
		v, err := vi.loadVec(args[0])
		if err != nil {
			return err
		}
		if hasMask {
			lanes := vi.totalBits / laneBits
			vecTy := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
			oldRaw, err := vi.loadReg(args[1].Reg)
			if err != nil {
				return err
			}
			vTyped, oldTyped := v, oldRaw
			if vecTy != vi.byteVecTy {
				t1, t2 := c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", t1, vi.byteVecTy, v, vecTy)
				fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", t2, vi.byteVecTy, oldRaw, vecTy)
				vTyped, oldTyped = "%"+t1, "%"+t2
			}
			blended, err := c.x86ApplyMask(kreg, zeroMask, lanes, vecTy, vTyped, oldTyped)
			if err != nil {
				return err
			}
			if vecTy != vi.byteVecTy {
				bc := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bc, vecTy, blended, vi.byteVecTy)
				v = "%" + bc
			} else {
				v = blended
			}
		}
		return vi.storeVec(args[1].Reg, v)
	}
	if args[0].Kind == asm.OpReg && (args[1].Kind == asm.OpMem || args[1].Kind == asm.OpSym) {
		vi, ok := c.x86VecInfoForReg(args[0].Reg)
		if !ok {
			return fmt.Errorf("amd64 %s src must be vector reg: %q", spec.Op, ins.Raw)
		}
		v, err := vi.loadReg(args[0].Reg)
		if err != nil {
			return err
		}
		var p, ptrType string
		if args[1].Kind == asm.OpMem {
			p, ptrType, err = c.ptrFromMem(args[1].Mem)
		} else {
			p, err = c.ptrFromSB(args[1].Sym)
			ptrType = "ptr"
		}
		if err != nil {
			return err
		}
		if hasMask {
			lanes := vi.totalBits / laneBits
			vecTy := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
			oldMem := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load %s, %s %s, align 1\n", oldMem, vecTy, ptrType, p)
			vTyped := v
			if vecTy != vi.byteVecTy {
				t1 := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", t1, vi.byteVecTy, v, vecTy)
				vTyped = "%" + t1
			}
			blended, err := c.x86ApplyMask(kreg, false, lanes, vecTy, vTyped, "%"+oldMem)
			if err != nil {
				return err
			}
			fmt.Fprintf(c.b, "  store %s %s, %s %s, align 1\n", vecTy, blended, ptrType, p)
			return nil
		}
		fmt.Fprintf(c.b, "  store %s %s, %s %s, align 1\n", vi.byteVecTy, v, ptrType, p)
		return nil
	}
	return fmt.Errorf("amd64 %s unsupported operands: %q", spec.Op, ins.Raw)
}

func (c *amd64Ctx) lowerX86VecShiftDeclarative(spec asm.OpSpec, zeroMask bool, ins asm.Instr) error {
	args, kreg, hasMask := x86StripEVEXMask(ins.Args)
	var cntOp, srcOp, dstOp asm.Operand
	if spec.ThreeOp {
		if len(args) != 3 || args[2].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects count, src, dst: %q", spec.Op, ins.Raw)
		}
		cntOp, srcOp, dstOp = args[0], args[1], args[2]
	} else {
		if len(args) != 2 || args[1].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects count, dst: %q", spec.Op, ins.Raw)
		}
		cntOp, srcOp, dstOp = args[0], args[1], args[1]
	}
	vi, ok := c.x86VecInfoForReg(dstOp.Reg)
	if !ok {
		return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
	}
	srcRaw, err := vi.loadVec(srcOp)
	if err != nil {
		return err
	}
	if spec.LLVMOp == "shl_byte" || spec.LLVMOp == "lshr_byte" {
		if cntOp.Kind != asm.OpImm {
			return fmt.Errorf("amd64 %s expects $imm: %q", spec.Op, ins.Raw)
		}
		n := int(uint8(cntOp.Imm))
		if n > 16 {
			n = 16
		}
		totalBytes := vi.totalBits / 8
		mask := make([]string, totalBytes)
		for base := 0; base < totalBytes; base += 16 {
			for i := 0; i < 16; i++ {
				if spec.LLVMOp == "shl_byte" {
					if i < n {
						mask[base+i] = fmt.Sprintf("i32 %d", totalBytes)
					} else {
						mask[base+i] = fmt.Sprintf("i32 %d", base+i-n)
					}
				} else {
					if i+n >= 16 {
						mask[base+i] = fmt.Sprintf("i32 %d", totalBytes)
					} else {
						mask[base+i] = fmt.Sprintf("i32 %d", base+i+n)
					}
				}
			}
		}
		sh := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s zeroinitializer, <%d x i32> <%s>\n", sh, vi.byteVecTy, srcRaw, vi.byteVecTy, totalBytes, strings.Join(mask, ", "))
		return vi.storeVec(dstOp.Reg, "%"+sh)
	}

	laneBits := int(spec.LaneBits)
	lanes := vi.totalBits / laneBits
	elemTy := fmt.Sprintf("i%d", laneBits)
	vecTy := fmt.Sprintf("<%d x %s>", lanes, elemTy)
	srcV := srcRaw
	if vecTy != vi.byteVecTy {
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bc, vi.byteVecTy, srcRaw, vecTy)
		srcV = "%" + bc
	}
	if spec.LLVMOp == "vror" || spec.LLVMOp == "vrol" {
		if cntOp.Kind != asm.OpImm {
			return fmt.Errorf("amd64 %s expects $imm: %q", spec.Op, ins.Raw)
		}
		amt := uint64(cntOp.Imm) % uint64(laneBits)
		amtVec := x86IntSplat(lanes, laneBits, int64(amt))
		intr := "fshr"
		if spec.LLVMOp == "vrol" {
			intr = "fshl"
		}
		rot := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.v%di%d(%s %s, %s %s, %s %s)\n", rot, vecTy, intr, lanes, laneBits, vecTy, srcV, vecTy, srcV, vecTy, amtVec)
		res := "%" + rot
		if hasMask {
			oldRaw, err := vi.loadReg(dstOp.Reg)
			if err != nil {
				return err
			}
			obc := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", obc, vi.byteVecTy, oldRaw, vecTy)
			res, err = c.x86ApplyMask(kreg, zeroMask, lanes, vecTy, res, "%"+obc)
			if err != nil {
				return err
			}
		}
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bc, vecTy, res, vi.byteVecTy)
		return vi.storeVec(dstOp.Reg, "%"+bc)
	}
	if spec.LLVMOp == "vshl_var" || spec.LLVMOp == "vlshr_var" || spec.LLVMOp == "vashr_var" {
		cntRaw, err := vi.loadVec(cntOp)
		if err != nil {
			return err
		}
		cbc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", cbc, vi.byteVecTy, cntRaw, vecTy)
		limVec := x86IntSplat(lanes, laneBits, int64(laneBits))
		maxVec := x86IntSplat(lanes, laneBits, int64(laneBits-1))
		big, clamped, shv := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp uge %s %%%s, %s\n", big, vecTy, cbc, limVec)
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %%%s\n", clamped, lanes, big, vecTy, maxVec, vecTy, cbc)
		llvmOp := "shl"
		if spec.LLVMOp == "vlshr_var" {
			llvmOp = "lshr"
		} else if spec.LLVMOp == "vashr_var" {
			llvmOp = "ashr"
		}
		fmt.Fprintf(c.b, "  %%%s = %s %s %s, %%%s\n", shv, llvmOp, vecTy, srcV, clamped)
		res := "%" + shv
		if spec.LLVMOp != "vashr_var" {
			sel := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s zeroinitializer, %s %%%s\n", sel, lanes, big, vecTy, vecTy, shv)
			res = "%" + sel
		}
		if hasMask {
			oldRaw, err := vi.loadReg(dstOp.Reg)
			if err != nil {
				return err
			}
			obc := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", obc, vi.byteVecTy, oldRaw, vecTy)
			res, err = c.x86ApplyMask(kreg, zeroMask, lanes, vecTy, res, "%"+obc)
			if err != nil {
				return err
			}
		}
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bc, vecTy, res, vi.byteVecTy)
		return vi.storeVec(dstOp.Reg, "%"+bc)
	}
	var cntI64 string
	switch cntOp.Kind {
	case asm.OpImm:
		cntI64 = fmt.Sprintf("%d", uint8(cntOp.Imm))
	case asm.OpReg:
		if isAMD64MReg(cntOp.Reg) {
			cntI64, err = c.loadReg(cntOp.Reg)
		} else {
			cntI64, err = c.loadXLowI64(cntOp.Reg)
		}
	case asm.OpMem:
		cntI64, err = c.evalIntSized(cntOp, asm.I64)
	default:
		return fmt.Errorf("amd64 %s unsupported shift count: %q", spec.Op, ins.Raw)
	}
	if err != nil {
		return err
	}
	big := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp uge i64 %s, %d\n", big, cntI64, laneBits)
	clamped64 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 %d, i64 %s\n", clamped64, big, laneBits-1, cntI64)
	cntElem := "%" + clamped64
	if laneBits < 64 {
		tr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to %s\n", tr, clamped64, elemTy)
		cntElem = "%" + tr
	}
	ins0, splat, shv := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement %s undef, %s %s, i32 0\n", ins0, vecTy, elemTy, cntElem)
	fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <%d x i32> zeroinitializer\n", splat, vecTy, ins0, vecTy, lanes)
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %%%s\n", shv, spec.LLVMOp, vecTy, srcV, splat)
	res := "%" + shv
	if spec.LLVMOp != "ashr" {
		sel := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s zeroinitializer, %s %%%s\n", sel, big, vecTy, vecTy, shv)
		res = "%" + sel
	}
	if hasMask {
		oldRaw, err := vi.loadReg(dstOp.Reg)
		if err != nil {
			return err
		}
		oldV := oldRaw
		if vecTy != vi.byteVecTy {
			obc := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", obc, vi.byteVecTy, oldRaw, vecTy)
			oldV = "%" + obc
		}
		res, err = c.x86ApplyMask(kreg, zeroMask, lanes, vecTy, res, oldV)
		if err != nil {
			return err
		}
	}
	if vecTy != vi.byteVecTy {
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bc, vecTy, res, vi.byteVecTy)
		res = "%" + bc
	}
	return vi.storeVec(dstOp.Reg, res)
}

func (c *amd64Ctx) lowerX86VecShuffleDeclarative(spec asm.OpSpec, zeroMask bool, ins asm.Instr) error {
	args, kreg, hasMask := x86StripEVEXMask(ins.Args)
	switch spec.LLVMOp {
	case "movhlps", "movlhps":
		var aOp, bOp, dstOp asm.Operand
		if spec.ThreeOp {
			if len(args) != 3 || args[2].Kind != asm.OpReg {
				return fmt.Errorf("amd64 %s expects 3 operands: %q", spec.Op, ins.Raw)
			}
			aOp, bOp, dstOp = args[0], args[1], args[2]
		} else {
			if len(args) != 2 || args[1].Kind != asm.OpReg {
				return fmt.Errorf("amd64 %s expects 2 operands: %q", spec.Op, ins.Raw)
			}
			aOp, bOp, dstOp = args[0], args[1], args[1]
		}
		av, err := c.loadXVecOperand(aOp)
		if err != nil {
			return err
		}
		bv, err := c.loadXVecOperand(bOp)
		if err != nil {
			return err
		}
		ab, bb, sh, out := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", ab, av)
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", bb, bv)
		if spec.LLVMOp == "movhlps" {
			fmt.Fprintf(c.b, "  %%%s = shufflevector <2 x i64> %%%s, <2 x i64> %%%s, <2 x i32> <i32 1, i32 3>\n", sh, ab, bb)
		} else {
			fmt.Fprintf(c.b, "  %%%s = shufflevector <2 x i64> %%%s, <2 x i64> %%%s, <2 x i32> <i32 0, i32 2>\n", sh, bb, ab)
		}
		fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", out, sh)
		return c.storeX(dstOp.Reg, "%"+out)

	case "movmsk":
		if len(args) != 2 || args[0].Kind != asm.OpReg || args[1].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects Vsrc, dstReg: %q", spec.Op, ins.Raw)
		}
		vi, ok := c.x86VecInfoForReg(args[0].Reg)
		if !ok {
			return fmt.Errorf("amd64 %s src must be vector reg: %q", spec.Op, ins.Raw)
		}
		raw, err := vi.loadReg(args[0].Reg)
		if err != nil {
			return err
		}
		laneBits := int(spec.LaneBits)
		lanes := vi.totalBits / laneBits
		vecTy := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
		bc, cmp, bits := c.newTmp(), c.newTmp(), c.newTmp()
		if vecTy != vi.byteVecTy {
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bc, vi.byteVecTy, raw, vecTy)
			fmt.Fprintf(c.b, "  %%%s = icmp slt %s %%%s, zeroinitializer\n", cmp, vecTy, bc)
		} else {
			fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, zeroinitializer\n", cmp, vecTy, raw)
		}
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i1> %%%s to i%d\n", bits, lanes, cmp, lanes)
		res := "%" + bits
		if lanes < 32 {
			z := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i%d %%%s to i32\n", z, lanes, bits)
			res = "%" + z
		}
		return c.storeRegSized(args[1].Reg, asm.I32, res)

	case "pshufd":
		if len(args) != 3 || args[0].Kind != asm.OpImm || args[2].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects $imm, src, dst: %q", spec.Op, ins.Raw)
		}
		vi, ok := c.x86VecInfoForReg(args[2].Reg)
		if !ok {
			return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
		}
		raw, err := vi.loadVec(args[1])
		if err != nil {
			return err
		}
		lanes := vi.totalBits / 32
		vecTy := fmt.Sprintf("<%d x i32>", lanes)
		imm := args[0].Imm
		mask := make([]string, lanes)
		for base := 0; base < lanes; base += 4 {
			for i := 0; i < 4; i++ {
				mask[base+i] = fmt.Sprintf("i32 %d", base+int((imm>>(2*i))&3))
			}
		}
		bc, sh := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bc, vi.byteVecTy, raw, vecTy)
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <%d x i32> <%s>\n", sh, vecTy, bc, vecTy, lanes, strings.Join(mask, ", "))
		res := "%" + sh
		if hasMask {
			oldRaw, err := vi.loadReg(args[2].Reg)
			if err != nil {
				return err
			}
			obc := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", obc, vi.byteVecTy, oldRaw, vecTy)
			res, err = c.x86ApplyMask(kreg, zeroMask, lanes, vecTy, res, "%"+obc)
			if err != nil {
				return err
			}
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, vecTy, res, vi.byteVecTy)
		return vi.storeVec(args[2].Reg, "%"+out)

	case "vpshufb":
		if len(args) != 3 || args[2].Kind != asm.OpReg {
			return fmt.Errorf("amd64 VPSHUFB expects mask, src, dst: %q", ins.Raw)
		}
		vi, ok := c.x86VecInfoForReg(args[2].Reg)
		if !ok {
			return fmt.Errorf("amd64 VPSHUFB dst must be vector reg: %q", ins.Raw)
		}
		maskRaw, err := vi.loadVec(args[0])
		if err != nil {
			return err
		}
		srcRaw, err := vi.loadVec(args[1])
		if err != nil {
			return err
		}
		chunks := vi.totalBits / 128
		parts := make([]string, chunks)
		for ch := 0; ch < chunks; ch++ {
			sPart, mPart := srcRaw, maskRaw
			if chunks > 1 {
				st, mt := c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s poison, <16 x i32> %s\n", st, vi.byteVecTy, srcRaw, vi.byteVecTy, llvmI32RangeMask(ch*16, 16))
				fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s poison, <16 x i32> %s\n", mt, vi.byteVecTy, maskRaw, vi.byteVecTy, llvmI32RangeMask(ch*16, 16))
				sPart, mPart = "%"+st, "%"+mt
			}
			outCh := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call <16 x i8> @llvm.x86.ssse3.pshuf.b.128(<16 x i8> %s, <16 x i8> %s)\n", outCh, sPart, mPart)
			parts[ch] = "%" + outCh
		}
		res := parts[0]
		if chunks == 2 {
			m := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %s, <16 x i8> %s, <32 x i32> %s\n", m, parts[0], parts[1], llvmI32RangeMask(0, 32))
			res = "%" + m
		} else if chunks == 4 {
			m0, m1, m := c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %s, <16 x i8> %s, <32 x i32> %s\n", m0, parts[0], parts[1], llvmI32RangeMask(0, 32))
			fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %s, <16 x i8> %s, <32 x i32> %s\n", m1, parts[2], parts[3], llvmI32RangeMask(0, 32))
			fmt.Fprintf(c.b, "  %%%s = shufflevector <32 x i8> %%%s, <32 x i8> %%%s, <64 x i32> %s\n", m, m0, m1, llvmI32RangeMask(0, 64))
			res = "%" + m
		}
		if hasMask {
			oldRaw, err := vi.loadReg(args[2].Reg)
			if err != nil {
				return err
			}
			res, err = c.x86ApplyMask(kreg, zeroMask, vi.totalBits/8, vi.byteVecTy, res, oldRaw)
			if err != nil {
				return err
			}
		}
		return vi.storeVec(args[2].Reg, res)

	case "vpalignr":
		if len(args) != 4 || args[0].Kind != asm.OpImm || args[3].Kind != asm.OpReg {
			return fmt.Errorf("amd64 VPALIGNR expects $imm, src1, src2, dst: %q", ins.Raw)
		}
		vi, ok := c.x86VecInfoForReg(args[3].Reg)
		if !ok {
			return fmt.Errorf("amd64 VPALIGNR dst must be vector reg: %q", ins.Raw)
		}
		src1Raw, err := vi.loadVec(args[1])
		if err != nil {
			return err
		}
		src2Raw, err := vi.loadVec(args[2])
		if err != nil {
			return err
		}
		n := int(uint8(args[0].Imm))
		chunks := vi.totalBits / 128
		parts := make([]string, chunks)
		for ch := 0; ch < chunks; ch++ {
			s1, s2 := src1Raw, src2Raw
			if chunks > 1 {
				t1, t2 := c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s poison, <16 x i32> %s\n", t1, vi.byteVecTy, src1Raw, vi.byteVecTy, llvmI32RangeMask(ch*16, 16))
				fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s poison, <16 x i32> %s\n", t2, vi.byteVecTy, src2Raw, vi.byteVecTy, llvmI32RangeMask(ch*16, 16))
				s1, s2 = "%"+t1, "%"+t2
			}
			if n >= 32 {
				parts[ch] = "zeroinitializer"
				continue
			}
			cat := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %s, <16 x i8> %s, <32 x i32> %s\n", cat, s1, s2, llvmI32RangeMask(0, 32))
			mask := make([]string, 16)
			for i := 0; i < 16; i++ {
				if n+i < 32 {
					mask[i] = fmt.Sprintf("i32 %d", n+i)
				} else {
					mask[i] = "i32 32"
				}
			}
			al := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <32 x i8> %%%s, <32 x i8> zeroinitializer, <16 x i32> <%s>\n", al, cat, strings.Join(mask, ", "))
			parts[ch] = "%" + al
		}
		res := parts[0]
		if chunks == 2 {
			m := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %s, <16 x i8> %s, <32 x i32> %s\n", m, parts[0], parts[1], llvmI32RangeMask(0, 32))
			res = "%" + m
		} else if chunks == 4 {
			m0, m1, m := c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %s, <16 x i8> %s, <32 x i32> %s\n", m0, parts[0], parts[1], llvmI32RangeMask(0, 32))
			fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %s, <16 x i8> %s, <32 x i32> %s\n", m1, parts[2], parts[3], llvmI32RangeMask(0, 32))
			fmt.Fprintf(c.b, "  %%%s = shufflevector <32 x i8> %%%s, <32 x i8> %%%s, <64 x i32> %s\n", m, m0, m1, llvmI32RangeMask(0, 64))
			res = "%" + m
		}
		if hasMask {
			oldRaw, err := vi.loadReg(args[3].Reg)
			if err != nil {
				return err
			}
			res, err = c.x86ApplyMask(kreg, zeroMask, vi.totalBits/8, vi.byteVecTy, res, oldRaw)
			if err != nil {
				return err
			}
		}
		return vi.storeVec(args[3].Reg, res)

	case "pclmul":
		var imm int64
		var srcOp, lhsOp, dstOp asm.Operand
		if spec.ThreeOp {
			if len(args) != 4 || args[0].Kind != asm.OpImm || args[3].Kind != asm.OpReg {
				return fmt.Errorf("amd64 VPCLMULQDQ expects $imm, src1, src2, dst: %q", ins.Raw)
			}
			imm, srcOp, lhsOp, dstOp = args[0].Imm&0xff, args[1], args[2], args[3]
		} else {
			if len(args) != 3 || args[0].Kind != asm.OpImm || args[2].Kind != asm.OpReg {
				return fmt.Errorf("amd64 PCLMULQDQ expects $imm, src, dst: %q", ins.Raw)
			}
			imm, srcOp, lhsOp, dstOp = args[0].Imm&0xff, args[1], args[2], args[2]
		}
		vi, ok := c.x86VecInfoForReg(dstOp.Reg)
		if !ok {
			return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
		}
		srcRaw, err := vi.loadVec(srcOp)
		if err != nil {
			return err
		}
		lhsRaw, err := vi.loadVec(lhsOp)
		if err != nil {
			return err
		}
		chunks := vi.totalBits / 128
		nQ := vi.totalBits / 64
		qTy := fmt.Sprintf("<%d x i64>", nQ)
		lb, sb := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", lb, vi.byteVecTy, lhsRaw, qTy)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", sb, vi.byteVecTy, srcRaw, qTy)
		parts := make([]string, chunks)
		for ch := 0; ch < chunks; ch++ {
			dl, sl := "%"+lb, "%"+sb
			if chunks > 1 {
				t1, t2 := c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <2 x i32> <i32 %d, i32 %d>\n", t1, qTy, lb, qTy, ch*2, ch*2+1)
				fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <2 x i32> <i32 %d, i32 %d>\n", t2, qTy, sb, qTy, ch*2, ch*2+1)
				dl, sl = "%"+t1, "%"+t2
			}
			cl := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call <2 x i64> @llvm.x86.pclmulqdq(<2 x i64> %s, <2 x i64> %s, i8 %d)\n", cl, dl, sl, imm)
			parts[ch] = "%" + cl
		}
		merged := parts[0]
		if chunks == 2 {
			m := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <2 x i64> %s, <2 x i64> %s, <4 x i32> <i32 0, i32 1, i32 2, i32 3>\n", m, parts[0], parts[1])
			merged = "%" + m
		} else if chunks == 4 {
			m0, m1, m := c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <2 x i64> %s, <2 x i64> %s, <4 x i32> <i32 0, i32 1, i32 2, i32 3>\n", m0, parts[0], parts[1])
			fmt.Fprintf(c.b, "  %%%s = shufflevector <2 x i64> %s, <2 x i64> %s, <4 x i32> <i32 0, i32 1, i32 2, i32 3>\n", m1, parts[2], parts[3])
			fmt.Fprintf(c.b, "  %%%s = shufflevector <4 x i64> %%%s, <4 x i64> %%%s, <8 x i32> <i32 0, i32 1, i32 2, i32 3, i32 4, i32 5, i32 6, i32 7>\n", m, m0, m1)
			merged = "%" + m
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, qTy, merged, vi.byteVecTy)
		return vi.storeVec(dstOp.Reg, "%"+out)

	case "pshufw_lo", "pshufw_hi":
		if len(args) != 3 || args[0].Kind != asm.OpImm || args[2].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects $imm, src, dst: %q", spec.Op, ins.Raw)
		}
		vi, ok := c.x86VecInfoForReg(args[2].Reg)
		if !ok {
			return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
		}
		raw, err := vi.loadVec(args[1])
		if err != nil {
			return err
		}
		lanes := vi.totalBits / 16
		vecTy := fmt.Sprintf("<%d x i16>", lanes)
		imm := args[0].Imm
		mask := make([]string, lanes)
		for laneBase := 0; laneBase < lanes; laneBase += 8 {
			for i := 0; i < 8; i++ {
				idx := laneBase + i
				if spec.LLVMOp == "pshufw_lo" && i < 4 {
					idx = laneBase + int((imm>>(2*i))&3)
				} else if spec.LLVMOp == "pshufw_hi" && i >= 4 {
					idx = laneBase + 4 + int((imm>>(2*(i-4)))&3)
				}
				mask[laneBase+i] = fmt.Sprintf("i32 %d", idx)
			}
		}
		bc, sh := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bc, vi.byteVecTy, raw, vecTy)
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <%d x i32> <%s>\n", sh, vecTy, bc, vecTy, lanes, strings.Join(mask, ", "))
		res := "%" + sh
		if hasMask {
			oldRaw, err := vi.loadReg(args[2].Reg)
			if err != nil {
				return err
			}
			obc := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", obc, vi.byteVecTy, oldRaw, vecTy)
			res, err = c.x86ApplyMask(kreg, zeroMask, lanes, vecTy, res, "%"+obc)
			if err != nil {
				return err
			}
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, vecTy, res, vi.byteVecTy)
		return vi.storeVec(args[2].Reg, "%"+out)

	case "shufp":
		var imm int64
		var rhsOp, lhsOp, dstOp asm.Operand
		if spec.ThreeOp {
			if len(args) != 4 || args[0].Kind != asm.OpImm || args[3].Kind != asm.OpReg {
				return fmt.Errorf("amd64 %s expects $imm, src1, src2, dst: %q", spec.Op, ins.Raw)
			}
			imm, rhsOp, lhsOp, dstOp = args[0].Imm, args[1], args[2], args[3]
		} else {
			if len(args) != 3 || args[0].Kind != asm.OpImm || args[2].Kind != asm.OpReg {
				return fmt.Errorf("amd64 %s expects $imm, src, dst: %q", spec.Op, ins.Raw)
			}
			imm, rhsOp, lhsOp, dstOp = args[0].Imm, args[1], args[2], args[2]
		}
		vi, ok := c.x86VecInfoForReg(dstOp.Reg)
		if !ok {
			return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
		}
		lhsRaw, err := vi.loadVec(lhsOp)
		if err != nil {
			return err
		}
		rhsRaw, err := vi.loadVec(rhsOp)
		if err != nil {
			return err
		}
		laneBits := int(spec.LaneBits)
		lanes := vi.totalBits / laneBits
		vecTy := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
		per128 := 128 / laneBits
		mask := make([]string, lanes)
		for base := 0; base < lanes; base += per128 {
			if laneBits == 64 {
				// SHUFPD: 1 bit per 64-bit lane
				laneGroup := base / 2
				b0 := int((imm >> uint(laneGroup*2)) & 1)
				b1 := int((imm >> uint(laneGroup*2+1)) & 1)
				mask[base] = fmt.Sprintf("i32 %d", base+b0)
				mask[base+1] = fmt.Sprintf("i32 %d", lanes+base+b1)
			} else {
				mask[base] = fmt.Sprintf("i32 %d", base+int((imm>>0)&3))
				mask[base+1] = fmt.Sprintf("i32 %d", base+int((imm>>2)&3))
				mask[base+2] = fmt.Sprintf("i32 %d", lanes+base+int((imm>>4)&3))
				mask[base+3] = fmt.Sprintf("i32 %d", lanes+base+int((imm>>6)&3))
			}
		}
		lb, rb, sh := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", lb, vi.byteVecTy, lhsRaw, vecTy)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", rb, vi.byteVecTy, rhsRaw, vecTy)
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s %%%s, <%d x i32> <%s>\n", sh, vecTy, lb, vecTy, rb, lanes, strings.Join(mask, ", "))
		res := "%" + sh
		if hasMask {
			oldRaw, err := vi.loadReg(dstOp.Reg)
			if err != nil {
				return err
			}
			obc := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", obc, vi.byteVecTy, oldRaw, vecTy)
			res, err = c.x86ApplyMask(kreg, zeroMask, lanes, vecTy, res, "%"+obc)
			if err != nil {
				return err
			}
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, vecTy, res, vi.byteVecTy)
		return vi.storeVec(dstOp.Reg, "%"+out)

	case "unpckl", "unpckh":
		var rhsOp, lhsOp, dstOp asm.Operand
		if spec.ThreeOp {
			if len(args) != 3 || args[2].Kind != asm.OpReg {
				return fmt.Errorf("amd64 %s expects 3 operands: %q", spec.Op, ins.Raw)
			}
			rhsOp, lhsOp, dstOp = args[0], args[1], args[2]
		} else {
			if len(args) != 2 || args[1].Kind != asm.OpReg {
				return fmt.Errorf("amd64 %s expects 2 operands: %q", spec.Op, ins.Raw)
			}
			rhsOp, lhsOp, dstOp = args[0], args[1], args[1]
		}
		vi, ok := c.x86VecInfoForReg(dstOp.Reg)
		if !ok {
			return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
		}
		lhsRaw, err := vi.loadVec(lhsOp)
		if err != nil {
			return err
		}
		rhsRaw, err := vi.loadVec(rhsOp)
		if err != nil {
			return err
		}
		laneBits := int(spec.LaneBits)
		lanes := vi.totalBits / laneBits
		vecTy := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
		chunkBits := vi.totalBits
		if chunkBits > 128 {
			chunkBits = 128
		}
		per128 := chunkBits / laneBits
		half := per128 / 2
		off := 0
		if spec.LLVMOp == "unpckh" {
			off = half
		}
		mask := make([]string, lanes)
		for base := 0; base < lanes; base += per128 {
			for i := 0; i < half; i++ {
				mask[base+2*i] = fmt.Sprintf("i32 %d", base+off+i)
				mask[base+2*i+1] = fmt.Sprintf("i32 %d", lanes+base+off+i)
			}
		}
		lb, rb, sh := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", lb, vi.byteVecTy, lhsRaw, vecTy)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", rb, vi.byteVecTy, rhsRaw, vecTy)
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s %%%s, <%d x i32> <%s>\n", sh, vecTy, lb, vecTy, rb, lanes, strings.Join(mask, ", "))
		res := "%" + sh
		if hasMask {
			oldRaw, err := vi.loadReg(dstOp.Reg)
			if err != nil {
				return err
			}
			obc := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", obc, vi.byteVecTy, oldRaw, vecTy)
			res, err = c.x86ApplyMask(kreg, zeroMask, lanes, vecTy, res, "%"+obc)
			if err != nil {
				return err
			}
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, vecTy, res, vi.byteVecTy)
		return vi.storeVec(dstOp.Reg, "%"+out)

	case "blendm":
		// VPBLENDM{B,W,D,Q} src1, src2, [Kmask,] dst => Kmask ? src1 : src2 (or zero-masked)
		if len(args) != 3 || args[2].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects src1, src2, [K,] dst: %q", spec.Op, ins.Raw)
		}
		vi, ok := c.x86VecInfoForReg(args[2].Reg)
		if !ok {
			return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
		}
		rhsRaw, err := vi.loadVec(args[0])
		if err != nil {
			return err
		}
		lhsRaw, err := vi.loadVec(args[1])
		if err != nil {
			return err
		}
		laneBits := int(spec.LaneBits)
		lanes := vi.totalBits / laneBits
		vecTy := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
		rb, lb := rhsRaw, lhsRaw
		if vecTy != vi.byteVecTy {
			t1, t2 := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", t1, vi.byteVecTy, rhsRaw, vecTy)
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", t2, vi.byteVecTy, lhsRaw, vecTy)
			rb, lb = "%"+t1, "%"+t2
		}
		res := rb
		if hasMask {
			res, err = c.x86ApplyMask(kreg, zeroMask, lanes, vecTy, rb, lb)
			if err != nil {
				return err
			}
		}
		if vecTy != vi.byteVecTy {
			out := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, vecTy, res, vi.byteVecTy)
			res = "%" + out
		}
		return vi.storeVec(args[2].Reg, res)

	case "vbroadcast":
		if len(args) != 2 || args[1].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects src, Vdst: %q", spec.Op, ins.Raw)
		}
		vi, ok := c.x86VecInfoForReg(args[1].Reg)
		if !ok {
			return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
		}
		laneBits := int(spec.LaneBits)
		lanes := vi.totalBits / laneBits
		ty := x86LLVMIntType(uint16(laneBits))
		vecTy := fmt.Sprintf("<%d x %s>", lanes, ty)
		var elem string
		if args[0].Kind == asm.OpReg && isAMD64XReg(args[0].Reg) {
			xv, err := c.loadX(args[0].Reg)
			if err != nil {
				return err
			}
			srcTy := fmt.Sprintf("<%d x %s>", 128/laneBits, ty)
			xTyped := xv
			if srcTy != "<16 x i8>" {
				bc := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", bc, xv, srcTy)
				xTyped = "%" + bc
			}
			ex := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 0\n", ex, srcTy, xTyped)
			elem = "%" + ex
		} else {
			var err error
			elem, err = c.evalIntSized(args[0], ty)
			if err != nil {
				return err
			}
		}
		ins0, splat := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s undef, %s %s, i32 0\n", ins0, vecTy, ty, elem)
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <%d x i32> zeroinitializer\n", splat, vecTy, ins0, vecTy, lanes)
		res := "%" + splat
		if hasMask {
			oldRaw, err := vi.loadReg(args[1].Reg)
			if err != nil {
				return err
			}
			oldV := oldRaw
			if vecTy != vi.byteVecTy {
				obc := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", obc, vi.byteVecTy, oldRaw, vecTy)
				oldV = "%" + obc
			}
			res, err = c.x86ApplyMask(kreg, zeroMask, lanes, vecTy, res, oldV)
			if err != nil {
				return err
			}
		}
		if vecTy != vi.byteVecTy {
			out := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, vecTy, res, vi.byteVecTy)
			res = "%" + out
		}
		return vi.storeVec(args[1].Reg, res)

	case "vshuf_sub":
		// VSHUF{I,F}{32X4,64X2} $imm, src1, src2, [K,] dst (128-bit lane shuffles on 256/512-bit regs)
		if len(args) != 4 || args[0].Kind != asm.OpImm || args[3].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects $imm, src1, src2, dst: %q", spec.Op, ins.Raw)
		}
		vi, ok := c.x86VecInfoForReg(args[3].Reg)
		if !ok {
			return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
		}
		rhsRaw, err := vi.loadVec(args[1])
		if err != nil {
			return err
		}
		lhsRaw, err := vi.loadVec(args[2])
		if err != nil {
			return err
		}
		imm := args[0].Imm
		totalBytes := vi.totalBits / 8
		numChunks := totalBytes / 16
		mask := make([]string, totalBytes)
		for ch := 0; ch < numChunks; ch++ {
			var sel int
			if numChunks == 2 {
				sel = int((imm >> uint(ch)) & 1)
			} else {
				sel = int((imm >> uint(2*ch)) & 3)
			}
			srcBase := sel * 16
			if ch >= numChunks/2 {
				srcBase = totalBytes + sel*16
			}
			for b := 0; b < 16; b++ {
				mask[ch*16+b] = fmt.Sprintf("i32 %d", srcBase+b)
			}
		}
		sh := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s %s, <%d x i32> <%s>\n", sh, vi.byteVecTy, lhsRaw, vi.byteVecTy, rhsRaw, totalBytes, strings.Join(mask, ", "))
		res := "%" + sh
		if hasMask {
			laneBits := 32
			if strings.Contains(string(spec.Op), "64") {
				laneBits = 64
			}
			lanes := vi.totalBits / laneBits
			vecTy := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
			oldRaw, err := vi.loadReg(args[3].Reg)
			if err != nil {
				return err
			}
			rb, ob := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", rb, vi.byteVecTy, res, vecTy)
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", ob, vi.byteVecTy, oldRaw, vecTy)
			blended, err := c.x86ApplyMask(kreg, zeroMask, lanes, vecTy, "%"+rb, "%"+ob)
			if err != nil {
				return err
			}
			out := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, vecTy, blended, vi.byteVecTy)
			res = "%" + out
		}
		return vi.storeVec(args[3].Reg, res)

	case "movsldup", "movshdup", "movddup":
		if len(args) != 2 || args[1].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects src, dst: %q", spec.Op, ins.Raw)
		}
		vi, ok := c.x86VecInfoForReg(args[1].Reg)
		if !ok {
			return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
		}
		raw, err := vi.loadVec(args[0])
		if err != nil {
			return err
		}
		laneBits := int(spec.LaneBits)
		lanes := vi.totalBits / laneBits
		vecTy := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
		mask := make([]string, lanes)
		for i := 0; i < lanes; i++ {
			if spec.LLVMOp == "movshdup" {
				mask[i] = fmt.Sprintf("i32 %d", (i&^1)+1)
			} else {
				mask[i] = fmt.Sprintf("i32 %d", i&^1)
			}
		}
		bc, sh := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bc, vi.byteVecTy, raw, vecTy)
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <%d x i32> <%s>\n", sh, vecTy, bc, vecTy, lanes, strings.Join(mask, ", "))
		res := "%" + sh
		if hasMask {
			oldRaw, err := vi.loadReg(args[1].Reg)
			if err != nil {
				return err
			}
			obc := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", obc, vi.byteVecTy, oldRaw, vecTy)
			res, err = c.x86ApplyMask(kreg, zeroMask, lanes, vecTy, res, "%"+obc)
			if err != nil {
				return err
			}
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, vecTy, res, vi.byteVecTy)
		return vi.storeVec(args[1].Reg, "%"+out)

	case "blend_imm", "blendv":
		var selOp, rhsOp, lhsOp, dstOp asm.Operand
		if spec.ThreeOp {
			if len(args) != 4 || args[3].Kind != asm.OpReg {
				return fmt.Errorf("amd64 %s expects 4 operands: %q", spec.Op, ins.Raw)
			}
			selOp, rhsOp, lhsOp, dstOp = args[0], args[1], args[2], args[3]
		} else {
			if len(args) != 3 || args[2].Kind != asm.OpReg {
				return fmt.Errorf("amd64 %s expects 3 operands: %q", spec.Op, ins.Raw)
			}
			selOp, rhsOp, lhsOp, dstOp = args[0], args[1], args[2], args[2]
		}
		vi, ok := c.x86VecInfoForReg(dstOp.Reg)
		if !ok {
			return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
		}
		lhsRaw, err := vi.loadVec(lhsOp)
		if err != nil {
			return err
		}
		rhsRaw, err := vi.loadVec(rhsOp)
		if err != nil {
			return err
		}
		laneBits := int(spec.LaneBits)
		lanes := vi.totalBits / laneBits
		vecTy := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
		lb, rb := lhsRaw, rhsRaw
		if vecTy != vi.byteVecTy {
			t1, t2 := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", t1, vi.byteVecTy, lhsRaw, vecTy)
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", t2, vi.byteVecTy, rhsRaw, vecTy)
			lb, rb = "%"+t1, "%"+t2
		}
		var res string
		if spec.LLVMOp == "blend_imm" {
			if selOp.Kind != asm.OpImm {
				return fmt.Errorf("amd64 %s expects $imm: %q", spec.Op, ins.Raw)
			}
			imm := selOp.Imm
			per := lanes
			if laneBits == 16 && lanes > 8 {
				per = 8
			}
			mask := make([]string, lanes)
			for i := 0; i < lanes; i++ {
				if (imm>>uint(i%per))&1 != 0 {
					mask[i] = fmt.Sprintf("i32 %d", lanes+i)
				} else {
					mask[i] = fmt.Sprintf("i32 %d", i)
				}
			}
			sh := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s %s, <%d x i32> <%s>\n", sh, vecTy, lb, vecTy, rb, lanes, strings.Join(mask, ", "))
			res = "%" + sh
		} else {
			svRaw, err := vi.loadVec(selOp)
			if err != nil {
				return err
			}
			sv := svRaw
			if vecTy != vi.byteVecTy {
				sb := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", sb, vi.byteVecTy, svRaw, vecTy)
				sv = "%" + sb
			}
			cmp, sel := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, zeroinitializer\n", cmp, vecTy, sv)
			fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %s\n", sel, lanes, cmp, vecTy, rb, vecTy, lb)
			res = "%" + sel
		}
		if vecTy != vi.byteVecTy {
			out := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, vecTy, res, vi.byteVecTy)
			res = "%" + out
		}
		return vi.storeVec(dstOp.Reg, res)

	case "pack":
		var rhsOp, lhsOp, dstOp asm.Operand
		if spec.ThreeOp {
			if len(args) != 3 || args[2].Kind != asm.OpReg {
				return fmt.Errorf("amd64 %s expects 3 operands: %q", spec.Op, ins.Raw)
			}
			rhsOp, lhsOp, dstOp = args[0], args[1], args[2]
		} else {
			if len(args) != 2 || args[1].Kind != asm.OpReg {
				return fmt.Errorf("amd64 %s expects 2 operands: %q", spec.Op, ins.Raw)
			}
			rhsOp, lhsOp, dstOp = args[0], args[1], args[1]
		}
		vi, ok := c.x86VecInfoForReg(dstOp.Reg)
		if !ok {
			return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
		}
		lhsRaw, err := vi.loadVec(lhsOp)
		if err != nil {
			return err
		}
		rhsRaw, err := vi.loadVec(rhsOp)
		if err != nil {
			return err
		}
		srcBits := int(spec.SrcWidth)
		dstBits := int(spec.LaneBits)
		srcLanes := vi.totalBits / srcBits
		dstLanes := vi.totalBits / dstBits
		srcTy := fmt.Sprintf("<%d x i%d>", srcLanes, srcBits)
		dstTy := fmt.Sprintf("<%d x i%d>", dstLanes, dstBits)
		halfDstTy := fmt.Sprintf("<%d x i%d>", srcLanes, dstBits)
		clamp := func(raw string) string {
			bc := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bc, vi.byteVecTy, raw, srcTy)
			var loLit, hiLit int64
			if spec.Signed {
				loLit = -(int64(1) << (dstBits - 1))
				hiLit = (int64(1) << (dstBits - 1)) - 1
			} else {
				loLit = 0
				hiLit = (int64(1) << dstBits) - 1
			}
			loVec := x86IntSplat(srcLanes, srcBits, loLit)
			hiVec := x86IntSplat(srcLanes, srcBits, hiLit)
			cLo, sLo, cHi, sHi, tr := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp slt %s %%%s, %s\n", cLo, srcTy, bc, loVec)
			fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %%%s\n", sLo, srcLanes, cLo, srcTy, loVec, srcTy, bc)
			fmt.Fprintf(c.b, "  %%%s = icmp sgt %s %%%s, %s\n", cHi, srcTy, sLo, hiVec)
			fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %%%s\n", sHi, srcLanes, cHi, srcTy, hiVec, srcTy, sLo)
			fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", tr, srcTy, sHi, halfDstTy)
			return "%" + tr
		}
		lClamped := clamp(lhsRaw)
		rClamped := clamp(rhsRaw)
		// Interleave lanes per 128-bit chunk (or single 64-bit chunk for MMX).
		chunkBits := vi.totalBits
		if chunkBits > 128 {
			chunkBits = 128
		}
		srcPer128 := chunkBits / srcBits
		mask := make([]string, dstLanes)
		chunks := vi.totalBits / chunkBits
		for ch := 0; ch < chunks; ch++ {
			for i := 0; i < srcPer128; i++ {
				mask[ch*2*srcPer128+i] = fmt.Sprintf("i32 %d", ch*srcPer128+i)
				mask[ch*2*srcPer128+srcPer128+i] = fmt.Sprintf("i32 %d", srcLanes+ch*srcPer128+i)
			}
		}
		sh := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s %s, <%d x i32> <%s>\n", sh, halfDstTy, lClamped, halfDstTy, rClamped, dstLanes, strings.Join(mask, ", "))
		res := "%" + sh
		if dstTy != vi.byteVecTy {
			out := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, dstTy, res, vi.byteVecTy)
			res = "%" + out
		}
		return vi.storeVec(dstOp.Reg, res)

	case "valign":
		if len(args) != 4 || args[0].Kind != asm.OpImm || args[3].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects $imm, src1, src2, dst: %q", spec.Op, ins.Raw)
		}
		vi, ok := c.x86VecInfoForReg(args[3].Reg)
		if !ok {
			return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
		}
		loRaw, err := vi.loadVec(args[1])
		if err != nil {
			return err
		}
		hiRaw, err := vi.loadVec(args[2])
		if err != nil {
			return err
		}
		laneBits := int(spec.LaneBits)
		lanes := vi.totalBits / laneBits
		vecTy := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
		shift := int(args[0].Imm) % lanes
		mask := make([]string, lanes)
		for i := 0; i < lanes; i++ {
			mask[i] = fmt.Sprintf("i32 %d", shift+i)
		}
		lb, hb, sh := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", lb, vi.byteVecTy, loRaw, vecTy)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", hb, vi.byteVecTy, hiRaw, vecTy)
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s %%%s, <%d x i32> <%s>\n", sh, vecTy, lb, vecTy, hb, lanes, strings.Join(mask, ", "))
		res := "%" + sh
		if hasMask {
			oldRaw, err := vi.loadReg(args[3].Reg)
			if err != nil {
				return err
			}
			obc := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", obc, vi.byteVecTy, oldRaw, vecTy)
			res, err = c.x86ApplyMask(kreg, zeroMask, lanes, vecTy, res, "%"+obc)
			if err != nil {
				return err
			}
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, vecTy, res, vi.byteVecTy)
		return vi.storeVec(args[3].Reg, "%"+out)

	case "vpermil", "vpermq":
		if len(args) != 3 || args[2].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects 3 operands: %q", spec.Op, ins.Raw)
		}
		vi, ok := c.x86VecInfoForReg(args[2].Reg)
		if !ok {
			return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
		}
		laneBits := int(spec.LaneBits)
		lanes := vi.totalBits / laneBits
		vecTy := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
		if args[0].Kind == asm.OpImm {
			raw, err := vi.loadVec(args[1])
			if err != nil {
				return err
			}
			imm := args[0].Imm
			mask := make([]string, lanes)
			if spec.LLVMOp == "vpermq" {
				for base := 0; base < lanes; base += 4 {
					for i := 0; i < 4; i++ {
						mask[base+i] = fmt.Sprintf("i32 %d", base+int((imm>>(2*i))&3))
					}
				}
			} else {
				per128 := 128 / laneBits
				for base := 0; base < lanes; base += per128 {
					for i := 0; i < per128; i++ {
						if laneBits == 64 {
							bit := int((imm >> uint((base/2)*2+i)) & 1)
							mask[base+i] = fmt.Sprintf("i32 %d", base+bit)
						} else {
							mask[base+i] = fmt.Sprintf("i32 %d", base+int((imm>>(2*i))&3))
						}
					}
				}
			}
			bc, sh := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bc, vi.byteVecTy, raw, vecTy)
			fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <%d x i32> <%s>\n", sh, vecTy, bc, vecTy, lanes, strings.Join(mask, ", "))
			res := "%" + sh
			if hasMask {
				oldRaw, err := vi.loadReg(args[2].Reg)
				if err != nil {
					return err
				}
				obc := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", obc, vi.byteVecTy, oldRaw, vecTy)
				res, err = c.x86ApplyMask(kreg, zeroMask, lanes, vecTy, res, "%"+obc)
				if err != nil {
					return err
				}
			}
			out := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, vecTy, res, vi.byteVecTy)
			return vi.storeVec(args[2].Reg, "%"+out)
		}
		// Variable control vector form: OP ctrl, src, dst
		ctrlRaw, err := vi.loadVec(args[0])
		if err != nil {
			return err
		}
		srcRaw, err := vi.loadVec(args[1])
		if err != nil {
			return err
		}
		cb, sb := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", cb, vi.byteVecTy, ctrlRaw, vecTy)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", sb, vi.byteVecTy, srcRaw, vecTy)
		cur := "undef"
		per128 := 128 / laneBits
		for i := 0; i < lanes; i++ {
			base := (i / per128) * per128
			cEl, idx, ex, insE := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 %d\n", cEl, vecTy, cb, i)
			if laneBits == 64 {
				sh1 := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = lshr i64 %%%s, 1\n", sh1, cEl)
				fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, 1\n", idx, sh1)
				idx32 := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", idx32, idx)
				addB := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = add i32 %%%s, %d\n", addB, idx32, base)
				fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 %%%s\n", ex, vecTy, sb, addB)
			} else {
				fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, 3\n", idx, cEl)
				addB := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = add i32 %%%s, %d\n", addB, idx, base)
				fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 %%%s\n", ex, vecTy, sb, addB)
			}
			fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, i%d %%%s, i32 %d\n", insE, vecTy, cur, laneBits, ex, i)
			cur = "%" + insE
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, vecTy, cur, vi.byteVecTy)
		return vi.storeVec(args[2].Reg, "%"+out)

	case "vextract_sub":
		if len(args) != 3 || args[0].Kind != asm.OpImm {
			return fmt.Errorf("amd64 %s expects $imm, src, dst: %q", spec.Op, ins.Raw)
		}
		srcInfo, ok := c.x86VecInfoForReg(args[1].Reg)
		if !ok {
			return fmt.Errorf("amd64 %s src must be vector reg: %q", spec.Op, ins.Raw)
		}
		srcRaw, err := srcInfo.loadReg(args[1].Reg)
		if err != nil {
			return err
		}
		subBytes := int(spec.Width) / 8
		numSlices := (srcInfo.totalBits / 8) / subBytes
		idx := int(args[0].Imm) % numSlices
		start := idx * subBytes
		mask := make([]string, subBytes)
		for i := 0; i < subBytes; i++ {
			mask[i] = fmt.Sprintf("i32 %d", start+i)
		}
		sh := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s poison, <%d x i32> <%s>\n", sh, srcInfo.byteVecTy, srcRaw, srcInfo.byteVecTy, subBytes, strings.Join(mask, ", "))
		res := "%" + sh
		if args[2].Kind == asm.OpReg {
			dstInfo, ok := c.x86VecInfoForReg(args[2].Reg)
			if !ok {
				return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
			}
			if hasMask {
				laneBits := 32
				if strings.Contains(string(spec.Op), "64") {
					laneBits = 64
				}
				lanes := int(spec.Width) / laneBits
				vecTy := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
				oldRaw, err := dstInfo.loadReg(args[2].Reg)
				if err != nil {
					return err
				}
				rb, ob := c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", rb, dstInfo.byteVecTy, res, vecTy)
				fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", ob, dstInfo.byteVecTy, oldRaw, vecTy)
				blended, err := c.x86ApplyMask(kreg, zeroMask, lanes, vecTy, "%"+rb, "%"+ob)
				if err != nil {
					return err
				}
				bc := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bc, vecTy, blended, dstInfo.byteVecTy)
				res = "%" + bc
			}
			return dstInfo.storeVec(args[2].Reg, res)
		}
		if args[2].Kind == asm.OpMem {
			p, ptrType, err := c.ptrFromMem(args[2].Mem)
			if err != nil {
				return err
			}
			fmt.Fprintf(c.b, "  store <%d x i8> %s, %s %s, align 1\n", subBytes, res, ptrType, p)
			return nil
		}
		return fmt.Errorf("amd64 %s unsupported dst: %q", spec.Op, ins.Raw)

	case "vinsert_sub":
		if len(args) != 4 || args[0].Kind != asm.OpImm || args[3].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects $imm, subSrc, fullSrc, dst: %q", spec.Op, ins.Raw)
		}
		dstInfo, ok := c.x86VecInfoForReg(args[3].Reg)
		if !ok {
			return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
		}
		fullBytes := dstInfo.totalBits / 8
		subBytes := int(spec.Width) / 8
		fullRaw, err := dstInfo.loadVec(args[2])
		if err != nil {
			return err
		}
		var subRaw string
		if subBytes == 16 {
			subRaw, err = c.loadXVecOperand(args[1])
		} else {
			subRaw, err = c.loadYVecOperand(args[1])
		}
		if err != nil {
			return err
		}
		// Pad subRaw to fullBytes so shufflevector has matching input vector lengths.
		padMask := make([]string, fullBytes)
		for i := 0; i < subBytes; i++ {
			padMask[i] = fmt.Sprintf("i32 %d", i)
		}
		for i := subBytes; i < fullBytes; i++ {
			padMask[i] = "i32 0"
		}
		padded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i8> %s, <%d x i8> poison, <%d x i32> <%s>\n", padded, subBytes, subRaw, subBytes, fullBytes, strings.Join(padMask, ", "))
		numSlices := fullBytes / subBytes
		idx := int(args[0].Imm) % numSlices
		start := idx * subBytes
		blendMask := make([]string, fullBytes)
		for i := 0; i < fullBytes; i++ {
			if i >= start && i < start+subBytes {
				blendMask[i] = fmt.Sprintf("i32 %d", fullBytes+(i-start))
			} else {
				blendMask[i] = fmt.Sprintf("i32 %d", i)
			}
		}
		sh := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s %%%s, <%d x i32> <%s>\n", sh, dstInfo.byteVecTy, fullRaw, dstInfo.byteVecTy, padded, fullBytes, strings.Join(blendMask, ", "))
		res := "%" + sh
		if hasMask {
			laneBits := 32
			if strings.Contains(string(spec.Op), "64") {
				laneBits = 64
			}
			lanes := dstInfo.totalBits / laneBits
			vecTy := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
			oldRaw, err := dstInfo.loadReg(args[3].Reg)
			if err != nil {
				return err
			}
			rb, ob := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", rb, dstInfo.byteVecTy, res, vecTy)
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", ob, dstInfo.byteVecTy, oldRaw, vecTy)
			blended, err := c.x86ApplyMask(kreg, zeroMask, lanes, vecTy, "%"+rb, "%"+ob)
			if err != nil {
				return err
			}
			bc := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bc, vecTy, blended, dstInfo.byteVecTy)
			res = "%" + bc
		}
		return dstInfo.storeVec(args[3].Reg, res)

	case "vpextr":
		if len(args) != 3 || args[0].Kind != asm.OpImm {
			return fmt.Errorf("amd64 %s expects $imm, Xsrc, dst: %q", spec.Op, ins.Raw)
		}
		raw, err := c.loadXVecOperand(args[1])
		if err != nil {
			return err
		}
		laneBits := int(spec.LaneBits)
		lanes := 128 / laneBits
		ty := x86LLVMIntType(uint16(laneBits))
		vecTy := fmt.Sprintf("<%d x %s>", lanes, ty)
		lane := int(args[0].Imm) % lanes
		bc, ex := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", bc, raw, vecTy)
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 %d\n", ex, vecTy, bc, lane)
		switch args[2].Kind {
		case asm.OpReg:
			if laneBits < 32 {
				z := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = zext %s %%%s to i32\n", z, ty, ex)
				return c.storeRegSized(args[2].Reg, asm.I32, "%"+z)
			}
			return c.storeRegSized(args[2].Reg, ty, "%"+ex)
		case asm.OpMem:
			p, ptrType, err := c.ptrFromMem(args[2].Mem)
			if err != nil {
				return err
			}
			fmt.Fprintf(c.b, "  store %s %%%s, %s %s, align 1\n", ty, ex, ptrType, p)
			return nil
		default:
			return fmt.Errorf("amd64 %s unsupported dst: %q", spec.Op, ins.Raw)
		}

	case "vpinsr":
		if len(args) != 4 || args[0].Kind != asm.OpImm || args[3].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects $imm, scalar, Xsrc, Xdst: %q", spec.Op, ins.Raw)
		}
		laneBits := int(spec.LaneBits)
		lanes := 128 / laneBits
		ty := x86LLVMIntType(uint16(laneBits))
		vecTy := fmt.Sprintf("<%d x %s>", lanes, ty)
		lane := int(args[0].Imm) % lanes
		sc, err := c.evalIntSized(args[1], ty)
		if err != nil {
			return err
		}
		base, err := c.loadXVecOperand(args[2])
		if err != nil {
			return err
		}
		bc, insE, out := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", bc, base, vecTy)
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %%%s, %s %s, i32 %d\n", insE, vecTy, bc, ty, sc, lane)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", out, vecTy, insE)
		return c.storeX(args[3].Reg, "%"+out)

	case "insertps":
		var imm int64
		var srcOp, baseOp, dstOp asm.Operand
		if spec.ThreeOp {
			if len(args) != 4 || args[0].Kind != asm.OpImm || args[3].Kind != asm.OpReg {
				return fmt.Errorf("amd64 VINSERTPS expects $imm, src, Xbase, Xdst: %q", ins.Raw)
			}
			imm, srcOp, baseOp, dstOp = args[0].Imm, args[1], args[2], args[3]
		} else {
			if len(args) != 3 || args[0].Kind != asm.OpImm || args[2].Kind != asm.OpReg {
				return fmt.Errorf("amd64 INSERTPS expects $imm, src, Xdst: %q", ins.Raw)
			}
			imm, srcOp, baseOp, dstOp = args[0].Imm, args[1], args[2], args[2]
		}
		baseRaw, err := c.loadXVecOperand(baseOp)
		if err != nil {
			return err
		}
		var el string
		if srcOp.Kind == asm.OpReg {
			sr, err := c.loadX(srcOp.Reg)
			if err != nil {
				return err
			}
			sbc, ex := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x float>\n", sbc, sr)
			fmt.Fprintf(c.b, "  %%%s = extractelement <4 x float> %%%s, i32 %d\n", ex, sbc, (imm>>6)&3)
			el = "%" + ex
		} else {
			el, err = c.evalF32(srcOp)
			if err != nil {
				return err
			}
		}
		bbc, insE := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x float>\n", bbc, baseRaw)
		fmt.Fprintf(c.b, "  %%%s = insertelement <4 x float> %%%s, float %s, i32 %d\n", insE, bbc, el, (imm>>4)&3)
		cur := "%" + insE
		for i := 0; i < 4; i++ {
			if (imm>>uint(i))&1 != 0 {
				z := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = insertelement <4 x float> %s, float 0.0, i32 %d\n", z, cur, i)
				cur = "%" + z
			}
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <4 x float> %s to <16 x i8>\n", out, cur)
		return c.storeX(dstOp.Reg, "%"+out)

	case "dp":
		var imm int64
		var rhsOp, lhsOp, dstOp asm.Operand
		if spec.ThreeOp {
			if len(args) != 4 || args[0].Kind != asm.OpImm || args[3].Kind != asm.OpReg {
				return fmt.Errorf("amd64 %s expects $imm, src1, src2, dst: %q", spec.Op, ins.Raw)
			}
			imm, rhsOp, lhsOp, dstOp = args[0].Imm, args[1], args[2], args[3]
		} else {
			if len(args) != 3 || args[0].Kind != asm.OpImm || args[2].Kind != asm.OpReg {
				return fmt.Errorf("amd64 %s expects $imm, src, dst: %q", spec.Op, ins.Raw)
			}
			imm, rhsOp, lhsOp, dstOp = args[0].Imm, args[1], args[2], args[2]
		}
		vi, ok := c.x86VecInfoForReg(dstOp.Reg)
		if !ok {
			return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
		}
		lhsRaw, err := vi.loadVec(lhsOp)
		if err != nil {
			return err
		}
		rhsRaw, err := vi.loadVec(rhsOp)
		if err != nil {
			return err
		}
		laneBits := int(spec.LaneBits)
		lanes := vi.totalBits / laneBits
		elemTy := "float"
		if laneBits == 64 {
			elemTy = "double"
		}
		vecTy := fmt.Sprintf("<%d x %s>", lanes, elemTy)
		lb, rb, prod := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", lb, vi.byteVecTy, lhsRaw, vecTy)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", rb, vi.byteVecTy, rhsRaw, vecTy)
		fmt.Fprintf(c.b, "  %%%s = fmul %s %%%s, %%%s\n", prod, vecTy, lb, rb)
		per128 := 128 / laneBits
		cur := "zeroinitializer"
		for base := 0; base < lanes; base += per128 {
			sum := "0.0"
			for i := 0; i < per128; i++ {
				if (imm>>uint(4+i))&1 != 0 {
					ex, add := c.newTmp(), c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 %d\n", ex, vecTy, prod, base+i)
					fmt.Fprintf(c.b, "  %%%s = fadd %s %s, %%%s\n", add, elemTy, sum, ex)
					sum = "%" + add
				}
			}
			for i := 0; i < per128; i++ {
				if (imm>>uint(i))&1 != 0 {
					insE := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, %s %s, i32 %d\n", insE, vecTy, cur, elemTy, sum, base+i)
					cur = "%" + insE
				}
			}
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, vecTy, cur, vi.byteVecTy)
		return vi.storeVec(dstOp.Reg, "%"+out)

	case "psadbw":
		var rhsOp, lhsOp, dstOp asm.Operand
		if spec.ThreeOp {
			if len(args) != 3 || args[2].Kind != asm.OpReg {
				return fmt.Errorf("amd64 VPSADBW expects 3 operands: %q", ins.Raw)
			}
			rhsOp, lhsOp, dstOp = args[0], args[1], args[2]
		} else {
			if len(args) != 2 || args[1].Kind != asm.OpReg {
				return fmt.Errorf("amd64 PSADBW expects 2 operands: %q", ins.Raw)
			}
			rhsOp, lhsOp, dstOp = args[0], args[1], args[1]
		}
		vi, ok := c.x86VecInfoForReg(dstOp.Reg)
		if !ok {
			return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
		}
		lhsRaw, err := vi.loadVec(lhsOp)
		if err != nil {
			return err
		}
		rhsRaw, err := vi.loadVec(rhsOp)
		if err != nil {
			return err
		}
		nBytes := vi.totalBits / 8
		nQwords := vi.totalBits / 64
		lz, rz, diff, absd := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext <%d x i8> %s to <%d x i16>\n", lz, nBytes, lhsRaw, nBytes)
		fmt.Fprintf(c.b, "  %%%s = zext <%d x i8> %s to <%d x i16>\n", rz, nBytes, rhsRaw, nBytes)
		fmt.Fprintf(c.b, "  %%%s = sub <%d x i16> %%%s, %%%s\n", diff, nBytes, lz, rz)
		fmt.Fprintf(c.b, "  %%%s = call <%d x i16> @llvm.abs.v%di16(<%d x i16> %%%s, i1 false)\n", absd, nBytes, nBytes, nBytes, diff)
		cur := "zeroinitializer"
		for q := 0; q < nQwords; q++ {
			sum := "0"
			for b := 0; b < 8; b++ {
				ex, add := c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i16> %%%s, i32 %d\n", ex, nBytes, absd, q*8+b)
				fmt.Fprintf(c.b, "  %%%s = add i16 %s, %%%s\n", add, sum, ex)
				sum = "%" + add
			}
			z64, insQ := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i16 %s to i64\n", z64, sum)
			fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i64> %s, i64 %%%s, i32 %d\n", insQ, nQwords, cur, z64, q)
			cur = "%" + insQ
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i64> %s to %s\n", out, nQwords, cur, vi.byteVecTy)
		return vi.storeVec(dstOp.Reg, "%"+out)

	case "phminposuw":
		if len(args) != 2 || args[1].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects src, Xdst: %q", spec.Op, ins.Raw)
		}
		raw, err := c.loadXVecOperand(args[0])
		if err != nil {
			return err
		}
		bc, minV := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <8 x i16>\n", bc, raw)
		fmt.Fprintf(c.b, "  %%%s = extractelement <8 x i16> %%%s, i32 0\n", minV, bc)
		curMin, curIdx := "%"+minV, "0"
		for i := 1; i < 8; i++ {
			el, cmp, nm, ni := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <8 x i16> %%%s, i32 %d\n", el, bc, i)
			fmt.Fprintf(c.b, "  %%%s = icmp ult i16 %%%s, %s\n", cmp, el, curMin)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i16 %%%s, i16 %s\n", nm, cmp, el, curMin)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i16 %d, i16 %s\n", ni, cmp, i, curIdx)
			curMin, curIdx = "%"+nm, "%"+ni
		}
		v0, v1, out := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <8 x i16> zeroinitializer, i16 %s, i32 0\n", v0, curMin)
		fmt.Fprintf(c.b, "  %%%s = insertelement <8 x i16> %%%s, i16 %s, i32 1\n", v1, v0, curIdx)
		fmt.Fprintf(c.b, "  %%%s = bitcast <8 x i16> %%%s to <16 x i8>\n", out, v1)
		return c.storeX(args[1].Reg, "%"+out)

	case "pcmpstr":
		if len(args) != 3 || args[0].Kind != asm.OpImm {
			return fmt.Errorf("amd64 %s expects $imm, src, Xreg: %q", spec.Op, ins.Raw)
		}
		imm := args[0].Imm & 255
		src1, err := c.loadXVecOperand(args[2])
		if err != nil {
			return err
		}
		src2, err := c.loadXVecOperand(args[1])
		if err != nil {
			return err
		}
		name := strings.TrimPrefix(strings.ToLower(string(spec.Op)), "v")
		isExplicit := strings.Contains(name, "estr")
		isMask := strings.HasSuffix(name, "m")
		if isExplicit {
			eax, err := c.evalIntSized(asm.Operand{Kind: asm.OpReg, Reg: asm.AX}, asm.I32)
			if err != nil {
				return err
			}
			edx, err := c.evalIntSized(asm.Operand{Kind: asm.OpReg, Reg: asm.DX}, asm.I32)
			if err != nil {
				return err
			}
			if isMask {
				t := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = call <16 x i8> @llvm.x86.sse42.pcmpestrm128(<16 x i8> %s, i32 %s, <16 x i8> %s, i32 %s, i8 %d)\n", t, src1, eax, src2, edx, imm)
				return c.storeX(asm.Reg("X0"), "%"+t)
			}
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.x86.sse42.pcmpestri128(<16 x i8> %s, i32 %s, <16 x i8> %s, i32 %s, i8 %d)\n", t, src1, eax, src2, edx, imm)
			return c.storeRegSized(asm.CX, asm.I32, "%"+t)
		}
		if isMask {
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call <16 x i8> @llvm.x86.sse42.pcmpistrm128(<16 x i8> %s, <16 x i8> %s, i8 %d)\n", t, src1, src2, imm)
			return c.storeX(asm.Reg("X0"), "%"+t)
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.x86.sse42.pcmpistri128(<16 x i8> %s, <16 x i8> %s, i8 %d)\n", t, src1, src2, imm)
		return c.storeRegSized(asm.CX, asm.I32, "%"+t)

	case "vpternlog":
		if len(args) != 4 || args[0].Kind != asm.OpImm || args[3].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects $imm, src1, src2, dst: %q", spec.Op, ins.Raw)
		}
		vi, ok := c.x86VecInfoForReg(args[3].Reg)
		if !ok {
			return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
		}
		bcst := strings.Contains(strings.ToUpper(string(ins.Op)), ".BCST")
		laneBits := int(spec.LaneBits)
		lanes := vi.totalBits / laneBits
		vecTy := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
		aRaw, err := c.x86LoadVecOrBcst(vi, args[1], bcst, laneBits)
		if err != nil {
			return err
		}
		bRaw, err := vi.loadVec(args[2])
		if err != nil {
			return err
		}
		cRaw, err := vi.loadReg(args[3].Reg)
		if err != nil {
			return err
		}
		// Plan 9 AT&T order: $imm, src3(r/m), src2, dst(src1).
		// Intel truth-table bit index = (dst<<2)|(src2<<1)|src3.
		imm := uint8(args[0].Imm)
		var resBytes string
		switch imm {
		case 0x00:
			resBytes = "zeroinitializer"
		case 0xff:
			resBytes = x86IntSplat(vi.totalBits/8, 8, -1)
		case 0x96:
			x1, x2 := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", x1, vi.byteVecTy, cRaw, bRaw)
			fmt.Fprintf(c.b, "  %%%s = xor %s %%%s, %s\n", x2, vi.byteVecTy, x1, aRaw)
			resBytes = "%" + x2
		default:
			ones := x86IntSplat(vi.totalBits/8, 8, -1)
			nc, nb, na := c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", nc, vi.byteVecTy, cRaw, ones)
			fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", nb, vi.byteVecTy, bRaw, ones)
			fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", na, vi.byteVecTy, aRaw, ones)
			acc := ""
			for bit := uint(0); bit < 8; bit++ {
				if (imm>>bit)&1 == 0 {
					continue
				}
				tc, tb, ta := "%"+nc, "%"+nb, "%"+na
				if bit&4 != 0 {
					tc = cRaw
				}
				if bit&2 != 0 {
					tb = bRaw
				}
				if bit&1 != 0 {
					ta = aRaw
				}
				m1, m2 := c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", m1, vi.byteVecTy, tc, tb)
				fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %s\n", m2, vi.byteVecTy, m1, ta)
				if acc == "" {
					acc = "%" + m2
				} else {
					o := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = or %s %s, %%%s\n", o, vi.byteVecTy, acc, m2)
					acc = "%" + o
				}
			}
			resBytes = acc
		}
		if hasMask {
			rb, ob := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", rb, vi.byteVecTy, resBytes, vecTy)
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", ob, vi.byteVecTy, cRaw, vecTy)
			blended, err := c.x86ApplyMask(kreg, zeroMask, lanes, vecTy, "%"+rb, "%"+ob)
			if err != nil {
				return err
			}
			out := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, vecTy, blended, vi.byteVecTy)
			resBytes = "%" + out
		}
		return vi.storeVec(args[3].Reg, resBytes)

	case "vpcmp":
		if len(args) != 4 || args[0].Kind != asm.OpImm || args[3].Kind != asm.OpReg || !isAMD64KReg(args[3].Reg) {
			return fmt.Errorf("amd64 %s expects $imm, src1, src2, [Kmask,] Kdst: %q", spec.Op, ins.Raw)
		}
		var vi x86VecInfo
		var ok bool
		if args[2].Kind == asm.OpReg {
			vi, ok = c.x86VecInfoForReg(args[2].Reg)
		}
		if !ok && args[1].Kind == asm.OpReg {
			vi, ok = c.x86VecInfoForReg(args[1].Reg)
		}
		if !ok {
			return fmt.Errorf("amd64 %s requires vector source register: %q", spec.Op, ins.Raw)
		}
		bcst := strings.Contains(strings.ToUpper(string(ins.Op)), ".BCST")
		laneBits := int(spec.LaneBits)
		lanes := vi.totalBits / laneBits
		vecTy := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
		rhsRaw, err := c.x86LoadVecOrBcst(vi, args[1], bcst, laneBits)
		if err != nil {
			return err
		}
		lhsRaw, err := vi.loadVec(args[2])
		if err != nil {
			return err
		}
		lhs, rhs := lhsRaw, rhsRaw
		if vecTy != vi.byteVecTy {
			lb, rb := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", lb, vi.byteVecTy, lhsRaw, vecTy)
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", rb, vi.byteVecTy, rhsRaw, vecTy)
			lhs, rhs = "%"+lb, "%"+rb
		}
		predIdx := args[0].Imm & 7
		var kv string
		if predIdx == 3 {
			kv = "0"
		} else if predIdx == 7 {
			if lanes == 64 {
				kv = "-1"
			} else {
				kv = fmt.Sprintf("%d", (uint64(1)<<uint(lanes))-1)
			}
		} else {
			var pred string
			if spec.Signed {
				pred = [8]string{"eq", "slt", "sle", "", "ne", "sge", "sgt", ""}[predIdx]
			} else {
				pred = [8]string{"eq", "ult", "ule", "", "ne", "uge", "ugt", ""}[predIdx]
			}
			cmp, bits := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp %s %s %s, %s\n", cmp, pred, vecTy, lhs, rhs)
			fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i1> %%%s to i%d\n", bits, lanes, cmp, lanes)
			kv = "%" + bits
			if lanes < 64 {
				z := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = zext i%d %%%s to i64\n", z, lanes, bits)
				kv = "%" + z
			}
		}
		if hasMask {
			km, err := c.loadK(kreg)
			if err != nil {
				return err
			}
			andK := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i64 %s, %s\n", andK, kv, km)
			kv = "%" + andK
		}
		return c.storeK(args[3].Reg, kv)

	case "vpcompress":
		if len(args) != 2 || args[0].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects Vsrc, [Kmask,] dst: %q", spec.Op, ins.Raw)
		}
		vi, ok := c.x86VecInfoForReg(args[0].Reg)
		if !ok {
			return fmt.Errorf("amd64 %s src must be vector reg: %q", spec.Op, ins.Raw)
		}
		srcRaw, err := vi.loadReg(args[0].Reg)
		if err != nil {
			return err
		}
		laneBits := int(spec.LaneBits)
		lanes := vi.totalBits / laneBits
		vecTy := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
		sv := srcRaw
		if vecTy != vi.byteVecTy {
			bc := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bc, vi.byteVecTy, srcRaw, vecTy)
			sv = "%" + bc
		}
		if args[1].Kind == asm.OpReg {
			dstVi, ok := c.x86VecInfoForReg(args[1].Reg)
			if !ok || dstVi.totalBits != vi.totalBits {
				return fmt.Errorf("amd64 %s dst register width mismatch: %q", spec.Op, ins.Raw)
			}
			if !hasMask {
				return dstVi.storeVec(args[1].Reg, srcRaw)
			}
			maskv, err := c.loadK(kreg)
			if err != nil {
				return err
			}
			outVec := "zeroinitializer"
			if !zeroMask {
				oldRaw, err := dstVi.loadReg(args[1].Reg)
				if err != nil {
					return err
				}
				if vecTy != vi.byteVecTy {
					obc := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", obc, vi.byteVecTy, oldRaw, vecTy)
					outVec = "%" + obc
				} else {
					outVec = oldRaw
				}
			}
			writePos := "0"
			for i := 0; i < lanes; i++ {
				bit := amd64MaskBitI1(c, maskv, i)
				lane, insE, sel, step, nextPos := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", lane, vecTy, sv, i)
				fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, i%d %%%s, i32 %s\n", insE, vecTy, outVec, laneBits, lane, writePos)
				fmt.Fprintf(c.b, "  %%%s = select i1 %s, %s %%%s, %s %s\n", sel, bit, vecTy, insE, vecTy, outVec)
				fmt.Fprintf(c.b, "  %%%s = zext i1 %s to i32\n", step, bit)
				fmt.Fprintf(c.b, "  %%%s = add i32 %s, %%%s\n", nextPos, writePos, step)
				outVec = "%" + sel
				writePos = "%" + nextPos
			}
			resBytes := outVec
			if vecTy != vi.byteVecTy {
				out := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, vecTy, outVec, vi.byteVecTy)
				resBytes = "%" + out
			}
			return dstVi.storeVec(args[1].Reg, resBytes)
		}
		if args[1].Kind == asm.OpMem || args[1].Kind == asm.OpSym {
			var basePtr, ptrType string
			if args[1].Kind == asm.OpMem {
				basePtr, ptrType, err = c.ptrFromMem(args[1].Mem)
			} else {
				basePtr, err = c.ptrFromSB(args[1].Sym)
				ptrType = "ptr"
			}
			if err != nil {
				return err
			}
			if !hasMask {
				fmt.Fprintf(c.b, "  store %s %s, %s %s, align 1\n", vi.byteVecTy, srcRaw, ptrType, basePtr)
				return nil
			}
			maskv, err := c.loadK(kreg)
			if err != nil {
				return err
			}
			writePos := "0"
			for i := 0; i < lanes; i++ {
				bit := amd64MaskBitI1(c, maskv, i)
				lane, gep, oldM, val, step, nextPos := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", lane, vecTy, sv, i)
				fmt.Fprintf(c.b, "  %%%s = getelementptr i%d, %s %s, i32 %s\n", gep, laneBits, ptrType, basePtr, writePos)
				fmt.Fprintf(c.b, "  %%%s = load i%d, %s %%%s, align 1\n", oldM, laneBits, ptrType, gep)
				fmt.Fprintf(c.b, "  %%%s = select i1 %s, i%d %%%s, i%d %%%s\n", val, bit, laneBits, lane, laneBits, oldM)
				fmt.Fprintf(c.b, "  store i%d %%%s, %s %%%s, align 1\n", laneBits, val, ptrType, gep)
				fmt.Fprintf(c.b, "  %%%s = zext i1 %s to i32\n", step, bit)
				fmt.Fprintf(c.b, "  %%%s = add i32 %s, %%%s\n", nextPos, writePos, step)
				writePos = "%" + nextPos
			}
			return nil
		}
		return fmt.Errorf("amd64 %s unsupported dst: %q", spec.Op, ins.Raw)

	case "vpermb", "vpermi2b":
		if len(args) != 3 || args[2].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects src1, src2, [Kmask,] dst: %q", spec.Op, ins.Raw)
		}
		vi, ok := c.x86VecInfoForReg(args[2].Reg)
		if !ok {
			return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
		}
		lanes := vi.totalBits / 8
		src1, err := vi.loadVec(args[0])
		if err != nil {
			return err
		}
		src2, err := vi.loadVec(args[1])
		if err != nil {
			return err
		}
		cur := "undef"
		if spec.LLVMOp == "vpermb" {
			// VPERMB table(src1), idx(src2), dst
			maskBits := lanes - 1
			for i := 0; i < lanes; i++ {
				ix, m, ex, insE := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", ix, vi.byteVecTy, src2, i)
				fmt.Fprintf(c.b, "  %%%s = and i8 %%%s, %d\n", m, ix, maskBits)
				fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i8 %%%s\n", ex, vi.byteVecTy, src1, m)
				fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, i8 %%%s, i32 %d\n", insE, vi.byteVecTy, cur, ex, i)
				cur = "%" + insE
			}
		} else {
			// VPERMI2B table2(src1), idx(src2), dst(table1)
			table1, err := vi.loadReg(args[2].Reg)
			if err != nil {
				return err
			}
			maskBits := lanes - 1
			for i := 0; i < lanes; i++ {
				ix, low, hiBit, isHi, e1, e2, pick, insE := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", ix, vi.byteVecTy, src2, i)
				fmt.Fprintf(c.b, "  %%%s = and i8 %%%s, %d\n", low, ix, maskBits)
				fmt.Fprintf(c.b, "  %%%s = and i8 %%%s, %d\n", hiBit, ix, lanes)
				fmt.Fprintf(c.b, "  %%%s = icmp ne i8 %%%s, 0\n", isHi, hiBit)
				fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i8 %%%s\n", e1, vi.byteVecTy, table1, low)
				fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i8 %%%s\n", e2, vi.byteVecTy, src1, low)
				fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i8 %%%s, i8 %%%s\n", pick, isHi, e2, e1)
				fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, i8 %%%s, i32 %d\n", insE, vi.byteVecTy, cur, pick, i)
				cur = "%" + insE
			}
		}
		if hasMask {
			oldRaw, err := vi.loadReg(args[2].Reg)
			if err != nil {
				return err
			}
			cur, err = c.x86ApplyMask(kreg, zeroMask, lanes, vi.byteVecTy, cur, oldRaw)
			if err != nil {
				return err
			}
		}
		return vi.storeVec(args[2].Reg, cur)
	}
	return fmt.Errorf("amd64: unhandled SIMD shuffle %s", spec.Op)
}

func (c *amd64Ctx) x86LoadVecOrBcst(vi x86VecInfo, op asm.Operand, bcst bool, laneBits int) (string, error) {
	if bcst && op.Kind == asm.OpMem {
		lanes := vi.totalBits / laneBits
		elemTy := fmt.Sprintf("i%d", laneBits)
		vecTy := fmt.Sprintf("<%d x %s>", lanes, elemTy)
		p, ptrType, err := c.ptrFromMem(op.Mem)
		if err != nil {
			return "", err
		}
		ld, ins0, splat := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load %s, %s %s, align 1\n", ld, elemTy, ptrType, p)
		fmt.Fprintf(c.b, "  %%%s = insertelement %s undef, %s %%%s, i32 0\n", ins0, vecTy, elemTy, ld)
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <%d x i32> zeroinitializer\n", splat, vecTy, ins0, vecTy, lanes)
		if vecTy == vi.byteVecTy {
			return "%" + splat, nil
		}
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to %s\n", bc, vecTy, splat, vi.byteVecTy)
		return "%" + bc, nil
	}
	return vi.loadVec(op)
}

func (c *amd64Ctx) lowerX86VAESDeclarative(spec asm.OpSpec, zeroMask bool, ins asm.Instr) error {
	args, kreg, hasMask := x86StripEVEXMask(ins.Args)
	switch spec.LLVMOp {
	case "gf2affine", "gf2affineinv", "gf2mul":
		bcst := strings.Contains(strings.ToUpper(string(ins.Op)), ".BCST")
		var matOp, srcOp, dstOp asm.Operand
		var imm int64
		if spec.LLVMOp == "gf2mul" {
			if len(args) != 3 || args[2].Kind != asm.OpReg {
				return fmt.Errorf("amd64 %s expects src1, src2, [K,] dst: %q", spec.Op, ins.Raw)
			}
			matOp, srcOp, dstOp = args[0], args[1], args[2]
		} else {
			if len(args) != 4 || args[0].Kind != asm.OpImm || args[3].Kind != asm.OpReg {
				return fmt.Errorf("amd64 %s expects $imm, mat, src, [K,] dst: %q", spec.Op, ins.Raw)
			}
			imm, matOp, srcOp, dstOp = args[0].Imm&255, args[1], args[2], args[3]
		}
		vi, ok := c.x86VecInfoForReg(dstOp.Reg)
		if !ok {
			return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
		}
		matRaw, err := c.x86LoadVecOrBcst(vi, matOp, bcst, 64)
		if err != nil {
			return err
		}
		srcRaw, err := vi.loadVec(srcOp)
		if err != nil {
			return err
		}
		nBytes := vi.totalBits / 8
		var res string
		if spec.LLVMOp == "gf2mul" {
			// Pure target-independent GF(2^8) multiply mod 0x11B (x^8 + x^4 + x^3 + x + 1).
			// Compiles cleanly on any x86 target (including -mcpu=haswell without +gfni).
			res = c.emitX86GF2P8MulB(vi.byteVecTy, nBytes, srcRaw, matRaw)
		} else {
			inBytes := srcRaw
			if spec.LLVMOp == "gf2affineinv" {
				// GF(2^8) multiplicative inverse: x^254 via addition chain in GF(2^8).
				inBytes = c.emitX86GF2P8InvB(vi.byteVecTy, nBytes, srcRaw)
			}
			// Exact 8-step vectorized GF(2) affine matrix transform per qword lane.
			acc := "zeroinitializer"
			for bit := 0; bit < 8; bit++ {
				rowIdx := 7 - bit
				shufMask := make([]string, nBytes)
				for i := 0; i < nBytes; i++ {
					shufMask[i] = fmt.Sprintf("i32 %d", (i/8)*8+rowIdx)
				}
				rowVec, prod, pop, par := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s poison, <%d x i32> <%s>\n",
					rowVec, vi.byteVecTy, matRaw, vi.byteVecTy, nBytes, strings.Join(shufMask, ", "))
				fmt.Fprintf(c.b, "  %%%s = and %s %s, %%%s\n", prod, vi.byteVecTy, inBytes, rowVec)
				fmt.Fprintf(c.b, "  %%%s = call %s @llvm.ctpop.v%di8(%s %%%s)\n", pop, vi.byteVecTy, nBytes, vi.byteVecTy, prod)
				fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %s\n", par, vi.byteVecTy, pop, x86IntSplat(nBytes, 8, 1))
				term := "%" + par
				if bit > 0 {
					sh := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = shl %s %s, %s\n", sh, vi.byteVecTy, term, x86IntSplat(nBytes, 8, int64(bit)))
					term = "%" + sh
				}
				if acc == "zeroinitializer" {
					acc = term
				} else {
					o := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = or %s %s, %s\n", o, vi.byteVecTy, acc, term)
					acc = "%" + o
				}
			}
			if imm != 0 {
				x := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", x, vi.byteVecTy, acc, x86IntSplat(nBytes, 8, imm))
				acc = "%" + x
			}
			res = acc
		}
		if hasMask {
			oldRaw, err := vi.loadReg(dstOp.Reg)
			if err != nil {
				return err
			}
			res, err = c.x86ApplyMask(kreg, zeroMask, nBytes, vi.byteVecTy, res, oldRaw)
			if err != nil {
				return err
			}
		}
		return vi.storeVec(dstOp.Reg, res)
	case "aesimc":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("amd64 VAESIMC expects src, Xdst: %q", ins.Raw)
		}
		src, err := c.loadXVecOperand(ins.Args[0])
		if err != nil {
			return err
		}
		bc, res, out := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", bc, src)
		fmt.Fprintf(c.b, "  %%%s = call <2 x i64> @llvm.x86.aesni.aesimc(<2 x i64> %%%s)\n", res, bc)
		fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", out, res)
		return c.storeX(ins.Args[1].Reg, "%"+out)
	case "aeskeygenassist":
		if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpImm || ins.Args[2].Kind != asm.OpReg {
			return fmt.Errorf("amd64 VAESKEYGENASSIST expects $imm, src, Xdst: %q", ins.Raw)
		}
		src, err := c.loadXVecOperand(ins.Args[1])
		if err != nil {
			return err
		}
		bc, res, out := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", bc, src)
		fmt.Fprintf(c.b, "  %%%s = call <2 x i64> @llvm.x86.aesni.aeskeygenassist(<2 x i64> %%%s, i8 %d)\n", res, bc, ins.Args[0].Imm&255)
		fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", out, res)
		return c.storeX(ins.Args[2].Reg, "%"+out)
	default:
		// VAESENC/VAESENCLAST/VAESDEC/VAESDECLAST key, state, dst (128/256/512-bit!)
		if len(ins.Args) != 3 || ins.Args[2].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects key, state, dst: %q", spec.Op, ins.Raw)
		}
		vi, ok := c.x86VecInfoForReg(ins.Args[2].Reg)
		if !ok {
			return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
		}
		keyRaw, err := vi.loadVec(ins.Args[0])
		if err != nil {
			return err
		}
		stRaw, err := vi.loadVec(ins.Args[1])
		if err != nil {
			return err
		}
		nQwords := vi.totalBits / 64
		qTy := fmt.Sprintf("<%d x i64>", nQwords)
		kb, sb := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", kb, vi.byteVecTy, keyRaw, qTy)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", sb, vi.byteVecTy, stRaw, qTy)
		intr := "llvm.x86.aesni." + spec.LLVMOp
		if vi.totalBits == 256 {
			intr += ".256"
		} else if vi.totalBits == 512 {
			intr += ".512"
		}
		res, out := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @%s(%s %%%s, %s %%%s)\n", res, qTy, intr, qTy, sb, qTy, kb)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to %s\n", out, qTy, res, vi.byteVecTy)
		return vi.storeVec(ins.Args[2].Reg, "%"+out)
	}
}

func (c *amd64Ctx) emitX86GF2P8MulB(vecTy string, nBytes int, a, b string) string {
	// Russian peasant multiplication in GF(2^8) modulo 0x11B (poly 0x1B).
	ones := x86IntSplat(nBytes, 8, 1)
	poly := x86IntSplat(nBytes, 8, 0x1b)
	acc := "zeroinitializer"
	curA := a
	curB := b
	for step := 0; step < 8; step++ {
		lsb, cmp, term, nxtAcc := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", lsb, vecTy, curB, ones)
		fmt.Fprintf(c.b, "  %%%s = icmp ne %s %%%s, zeroinitializer\n", cmp, vecTy, lsb)
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s zeroinitializer\n", term, nBytes, cmp, vecTy, curA, vecTy)
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, %%%s\n", nxtAcc, vecTy, acc, term)
		acc = "%" + nxtAcc
		if step < 7 {
			hi, shl, xpoly, nxtA, nxtB := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, zeroinitializer\n", hi, vecTy, curA)
			fmt.Fprintf(c.b, "  %%%s = shl %s %s, %s\n", shl, vecTy, curA, ones)
			fmt.Fprintf(c.b, "  %%%s = xor %s %%%s, %s\n", xpoly, vecTy, shl, poly)
			fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %%%s, %s %%%s\n", nxtA, nBytes, hi, vecTy, xpoly, vecTy, shl)
			fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %s\n", nxtB, vecTy, curB, ones)
			curA = "%" + nxtA
			curB = "%" + nxtB
		}
	}
	return acc
}

func (c *amd64Ctx) emitX86GF2P8InvB(vecTy string, nBytes int, x string) string {
	// x^254 in GF(2^8): x^(2+4+8+16+32+64+128) (and 0 -> 0).
	sq := c.emitX86GF2P8MulB(vecTy, nBytes, x, x) // x^2
	acc := sq
	cur := sq
	for i := 0; i < 6; i++ {
		cur = c.emitX86GF2P8MulB(vecTy, nBytes, cur, cur)
		acc = c.emitX86GF2P8MulB(vecTy, nBytes, acc, cur)
	}
	return acc
}

func x86IntSplat(lanes, bits int, val int64) string {
	elems := make([]string, lanes)
	for i := range elems {
		elems[i] = fmt.Sprintf("i%d %d", bits, val)
	}
	return "<" + strings.Join(elems, ", ") + ">"
}
