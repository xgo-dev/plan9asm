package x86

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// M2 Family 1 (FMA3 + 4FMA) and Family 2 (CVT*/VCVT*) declarative specs and
// parameterized LLVM IR lowering templates.
//
// Using compact static tables keeps compile-time SSA size minimal while
// covering all 62 FMA opcodes (541 forms) and 70 CVT opcodes (344 forms)
// across XMM/YMM/ZMM, memory, .BCST, K-masking, .Z, and rounding suffixes.

const (
	fmaModeAdd    uint16 = 0
	fmaModeSub    uint16 = 1
	fmaModeNAdd   uint16 = 2
	fmaModeNSub   uint16 = 3
	fmaModeAddSub uint16 = 4
	fmaModeSubAdd uint16 = 5

	fmaOrder132 uint16 = 0 << 4
	fmaOrder213 uint16 = 1 << 4
	fmaOrder231 uint16 = 2 << 4
	fmaOrder4x  uint16 = 3 << 4

	fmaScalarFlag uint16 = 1 << 8
)

const (
	cvtKindSInt uint16 = 0
	cvtKindUInt uint16 = 1
	cvtKindFP   uint16 = 2
	cvtKindFP16 uint16 = 3

	cvtScalarFlag uint16 = 1 << 8
	cvtImmFlag    uint16 = 1 << 9
	cvtMem128Flag uint16 = 1 << 10 // explicit X suffix (128-bit memory src)
	cvtMem256Flag uint16 = 1 << 11 // explicit Y suffix (256-bit memory src)
)

func cvtSub(srcKind, dstKind, flags uint16) uint16 {
	return srcKind | (dstKind << 4) | flags
}

var x86M2FMACVTSpecs = []asm.OpSpec{
	// Family 1: FMA3 (58 ops) + 4FMA (4 ops) = 62 ops
	{Op: "VFMADD132PS", Family: asm.FamilyVecFMA, SubOp: fmaModeAdd | fmaOrder132, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMADD213PS", Family: asm.FamilyVecFMA, SubOp: fmaModeAdd | fmaOrder213, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMADD231PS", Family: asm.FamilyVecFMA, SubOp: fmaModeAdd | fmaOrder231, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMADD132PD", Family: asm.FamilyVecFMA, SubOp: fmaModeAdd | fmaOrder132, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMADD213PD", Family: asm.FamilyVecFMA, SubOp: fmaModeAdd | fmaOrder213, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMADD231PD", Family: asm.FamilyVecFMA, SubOp: fmaModeAdd | fmaOrder231, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMADD132SS", Family: asm.FamilyVecFMA, SubOp: fmaModeAdd | fmaOrder132 | fmaScalarFlag, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMADD213SS", Family: asm.FamilyVecFMA, SubOp: fmaModeAdd | fmaOrder213 | fmaScalarFlag, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMADD231SS", Family: asm.FamilyVecFMA, SubOp: fmaModeAdd | fmaOrder231 | fmaScalarFlag, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMADD132SD", Family: asm.FamilyVecFMA, SubOp: fmaModeAdd | fmaOrder132 | fmaScalarFlag, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMADD213SD", Family: asm.FamilyVecFMA, SubOp: fmaModeAdd | fmaOrder213 | fmaScalarFlag, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMADD231SD", Family: asm.FamilyVecFMA, SubOp: fmaModeAdd | fmaOrder231 | fmaScalarFlag, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},

	{Op: "VFMSUB132PS", Family: asm.FamilyVecFMA, SubOp: fmaModeSub | fmaOrder132, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMSUB213PS", Family: asm.FamilyVecFMA, SubOp: fmaModeSub | fmaOrder213, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMSUB231PS", Family: asm.FamilyVecFMA, SubOp: fmaModeSub | fmaOrder231, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMSUB132PD", Family: asm.FamilyVecFMA, SubOp: fmaModeSub | fmaOrder132, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMSUB213PD", Family: asm.FamilyVecFMA, SubOp: fmaModeSub | fmaOrder213, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMSUB231PD", Family: asm.FamilyVecFMA, SubOp: fmaModeSub | fmaOrder231, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMSUB132SS", Family: asm.FamilyVecFMA, SubOp: fmaModeSub | fmaOrder132 | fmaScalarFlag, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMSUB213SS", Family: asm.FamilyVecFMA, SubOp: fmaModeSub | fmaOrder213 | fmaScalarFlag, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMSUB231SS", Family: asm.FamilyVecFMA, SubOp: fmaModeSub | fmaOrder231 | fmaScalarFlag, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMSUB132SD", Family: asm.FamilyVecFMA, SubOp: fmaModeSub | fmaOrder132 | fmaScalarFlag, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMSUB213SD", Family: asm.FamilyVecFMA, SubOp: fmaModeSub | fmaOrder213 | fmaScalarFlag, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMSUB231SD", Family: asm.FamilyVecFMA, SubOp: fmaModeSub | fmaOrder231 | fmaScalarFlag, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},

	{Op: "VFNMADD132PS", Family: asm.FamilyVecFMA, SubOp: fmaModeNAdd | fmaOrder132, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFNMADD213PS", Family: asm.FamilyVecFMA, SubOp: fmaModeNAdd | fmaOrder213, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFNMADD231PS", Family: asm.FamilyVecFMA, SubOp: fmaModeNAdd | fmaOrder231, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFNMADD132PD", Family: asm.FamilyVecFMA, SubOp: fmaModeNAdd | fmaOrder132, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFNMADD213PD", Family: asm.FamilyVecFMA, SubOp: fmaModeNAdd | fmaOrder213, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFNMADD231PD", Family: asm.FamilyVecFMA, SubOp: fmaModeNAdd | fmaOrder231, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFNMADD132SS", Family: asm.FamilyVecFMA, SubOp: fmaModeNAdd | fmaOrder132 | fmaScalarFlag, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFNMADD213SS", Family: asm.FamilyVecFMA, SubOp: fmaModeNAdd | fmaOrder213 | fmaScalarFlag, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFNMADD231SS", Family: asm.FamilyVecFMA, SubOp: fmaModeNAdd | fmaOrder231 | fmaScalarFlag, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFNMADD132SD", Family: asm.FamilyVecFMA, SubOp: fmaModeNAdd | fmaOrder132 | fmaScalarFlag, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFNMADD213SD", Family: asm.FamilyVecFMA, SubOp: fmaModeNAdd | fmaOrder213 | fmaScalarFlag, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFNMADD231SD", Family: asm.FamilyVecFMA, SubOp: fmaModeNAdd | fmaOrder231 | fmaScalarFlag, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},

	{Op: "VFNMSUB132PS", Family: asm.FamilyVecFMA, SubOp: fmaModeNSub | fmaOrder132, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFNMSUB213PS", Family: asm.FamilyVecFMA, SubOp: fmaModeNSub | fmaOrder213, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFNMSUB231PS", Family: asm.FamilyVecFMA, SubOp: fmaModeNSub | fmaOrder231, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFNMSUB132PD", Family: asm.FamilyVecFMA, SubOp: fmaModeNSub | fmaOrder132, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFNMSUB213PD", Family: asm.FamilyVecFMA, SubOp: fmaModeNSub | fmaOrder213, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFNMSUB231PD", Family: asm.FamilyVecFMA, SubOp: fmaModeNSub | fmaOrder231, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFNMSUB132SS", Family: asm.FamilyVecFMA, SubOp: fmaModeNSub | fmaOrder132 | fmaScalarFlag, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFNMSUB213SS", Family: asm.FamilyVecFMA, SubOp: fmaModeNSub | fmaOrder213 | fmaScalarFlag, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFNMSUB231SS", Family: asm.FamilyVecFMA, SubOp: fmaModeNSub | fmaOrder231 | fmaScalarFlag, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFNMSUB132SD", Family: asm.FamilyVecFMA, SubOp: fmaModeNSub | fmaOrder132 | fmaScalarFlag, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFNMSUB213SD", Family: asm.FamilyVecFMA, SubOp: fmaModeNSub | fmaOrder213 | fmaScalarFlag, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFNMSUB231SD", Family: asm.FamilyVecFMA, SubOp: fmaModeNSub | fmaOrder231 | fmaScalarFlag, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},

	{Op: "VFMADDSUB132PS", Family: asm.FamilyVecFMA, SubOp: fmaModeAddSub | fmaOrder132, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMADDSUB213PS", Family: asm.FamilyVecFMA, SubOp: fmaModeAddSub | fmaOrder213, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMADDSUB231PS", Family: asm.FamilyVecFMA, SubOp: fmaModeAddSub | fmaOrder231, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMADDSUB132PD", Family: asm.FamilyVecFMA, SubOp: fmaModeAddSub | fmaOrder132, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMADDSUB213PD", Family: asm.FamilyVecFMA, SubOp: fmaModeAddSub | fmaOrder213, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMADDSUB231PD", Family: asm.FamilyVecFMA, SubOp: fmaModeAddSub | fmaOrder231, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},

	{Op: "VFMSUBADD132PS", Family: asm.FamilyVecFMA, SubOp: fmaModeSubAdd | fmaOrder132, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMSUBADD213PS", Family: asm.FamilyVecFMA, SubOp: fmaModeSubAdd | fmaOrder213, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMSUBADD231PS", Family: asm.FamilyVecFMA, SubOp: fmaModeSubAdd | fmaOrder231, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMSUBADD132PD", Family: asm.FamilyVecFMA, SubOp: fmaModeSubAdd | fmaOrder132, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMSUBADD213PD", Family: asm.FamilyVecFMA, SubOp: fmaModeSubAdd | fmaOrder213, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "VFMSUBADD231PD", Family: asm.FamilyVecFMA, SubOp: fmaModeSubAdd | fmaOrder231, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},

	{Op: "V4FMADDPS", Family: asm.FamilyVecFMA, SubOp: fmaModeAdd | fmaOrder4x, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "V4FMADDSS", Family: asm.FamilyVecFMA, SubOp: fmaModeAdd | fmaOrder4x | fmaScalarFlag, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "V4FNMADDPS", Family: asm.FamilyVecFMA, SubOp: fmaModeNAdd | fmaOrder4x, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},
	{Op: "V4FNMADDSS", Family: asm.FamilyVecFMA, SubOp: fmaModeNAdd | fmaOrder4x | fmaScalarFlag, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite},

	// Family 2: Packed & Scalar Conversions (70 ops)
	// SSE legacy packed converts (PL = packed int32 / DQ)
	{Op: "CVTPD2PL", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindSInt, cvtMem128Flag), SrcWidth: 64, Width: 32, Effect: asm.EffectWriteOnly, LLVMOp: "cvt"},
	{Op: "CVTTPD2PL", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindSInt, cvtMem128Flag), SrcWidth: 64, Width: 32, Effect: asm.EffectWriteOnly, LLVMOp: "cvt"},
	{Op: "CVTPD2PS", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindFP, cvtMem128Flag), SrcWidth: 64, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "cvt"},
	{Op: "CVTPL2PD", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindSInt, cvtKindFP, 0), SrcWidth: 32, Width: 64, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "cvt"},
	{Op: "CVTPL2PS", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindSInt, cvtKindFP, 0), SrcWidth: 32, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "cvt"},
	{Op: "CVTPS2PD", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindFP, 0), SrcWidth: 32, Width: 64, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "cvt"},
	{Op: "CVTPS2PL", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindSInt, 0), SrcWidth: 32, Width: 32, Effect: asm.EffectWriteOnly, LLVMOp: "cvt"},
	{Op: "CVTTPS2PL", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindSInt, 0), SrcWidth: 32, Width: 32, Effect: asm.EffectWriteOnly, LLVMOp: "cvt"},

	// VEX/EVEX packed int <-> fp converts
	{Op: "VCVTDQ2PD", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindSInt, cvtKindFP, 0), SrcWidth: 32, Width: 64, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTDQ2PS", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindSInt, cvtKindFP, 0), SrcWidth: 32, Width: 32, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTUDQ2PD", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindUInt, cvtKindFP, 0), SrcWidth: 32, Width: 64, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTUDQ2PS", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindUInt, cvtKindFP, 0), SrcWidth: 32, Width: 32, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTQQ2PD", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindSInt, cvtKindFP, 0), SrcWidth: 64, Width: 64, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTQQ2PS", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindSInt, cvtKindFP, 0), SrcWidth: 64, Width: 32, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTQQ2PSX", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindSInt, cvtKindFP, cvtMem128Flag), SrcWidth: 64, Width: 32, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTQQ2PSY", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindSInt, cvtKindFP, cvtMem256Flag), SrcWidth: 64, Width: 32, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTUQQ2PD", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindUInt, cvtKindFP, 0), SrcWidth: 64, Width: 64, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTUQQ2PS", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindUInt, cvtKindFP, 0), SrcWidth: 64, Width: 32, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTUQQ2PSX", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindUInt, cvtKindFP, cvtMem128Flag), SrcWidth: 64, Width: 32, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTUQQ2PSY", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindUInt, cvtKindFP, cvtMem256Flag), SrcWidth: 64, Width: 32, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},

	{Op: "VCVTPD2DQ", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindSInt, 0), SrcWidth: 64, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTPD2DQX", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindSInt, cvtMem128Flag), SrcWidth: 64, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTPD2DQY", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindSInt, cvtMem256Flag), SrcWidth: 64, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTTPD2DQ", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindSInt, 0), SrcWidth: 64, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTTPD2DQX", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindSInt, cvtMem128Flag), SrcWidth: 64, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTTPD2DQY", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindSInt, cvtMem256Flag), SrcWidth: 64, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},

	{Op: "VCVTPD2UDQ", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindUInt, 0), SrcWidth: 64, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTPD2UDQX", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindUInt, cvtMem128Flag), SrcWidth: 64, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTPD2UDQY", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindUInt, cvtMem256Flag), SrcWidth: 64, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTTPD2UDQ", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindUInt, 0), SrcWidth: 64, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTTPD2UDQX", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindUInt, cvtMem128Flag), SrcWidth: 64, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTTPD2UDQY", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindUInt, cvtMem256Flag), SrcWidth: 64, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},

	{Op: "VCVTPD2PS", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindFP, 0), SrcWidth: 64, Width: 32, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTPD2PSX", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindFP, cvtMem128Flag), SrcWidth: 64, Width: 32, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTPD2PSY", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindFP, cvtMem256Flag), SrcWidth: 64, Width: 32, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTPS2PD", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindFP, 0), SrcWidth: 32, Width: 64, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},

	{Op: "VCVTPD2QQ", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindSInt, 0), SrcWidth: 64, Width: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTTPD2QQ", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindSInt, 0), SrcWidth: 64, Width: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTPD2UQQ", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindUInt, 0), SrcWidth: 64, Width: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTTPD2UQQ", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindUInt, 0), SrcWidth: 64, Width: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},

	{Op: "VCVTPS2DQ", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindSInt, 0), SrcWidth: 32, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTTPS2DQ", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindSInt, 0), SrcWidth: 32, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTPS2UDQ", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindUInt, 0), SrcWidth: 32, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTTPS2UDQ", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindUInt, 0), SrcWidth: 32, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTPS2QQ", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindSInt, 0), SrcWidth: 32, Width: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTTPS2QQ", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindSInt, 0), SrcWidth: 32, Width: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTPS2UQQ", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindUInt, 0), SrcWidth: 32, Width: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTTPS2UQQ", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindUInt, 0), SrcWidth: 32, Width: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},

	// FP16 (F16C / AVX-512)
	{Op: "VCVTPH2PS", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP16, cvtKindFP, 0), SrcWidth: 16, Width: 32, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTPS2PH", Family: asm.FamilyVecUnary, SubOp: cvtSub(cvtKindFP, cvtKindFP16, cvtImmFlag), SrcWidth: 32, Width: 16, Float: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},

	// Scalar VEX/EVEX converts (FP -> GPR and unsigned GPR -> FP)
	{Op: "VCVTSD2SI", Family: asm.FamilyFP, SubOp: cvtSub(cvtKindFP, cvtKindSInt, cvtScalarFlag), SrcWidth: 64, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTSD2SIQ", Family: asm.FamilyFP, SubOp: cvtSub(cvtKindFP, cvtKindSInt, cvtScalarFlag), SrcWidth: 64, Width: 64, Effect: asm.EffectWriteOnly, LLVMOp: "cvt"},
	{Op: "VCVTSD2USI", Family: asm.FamilyFP, SubOp: cvtSub(cvtKindFP, cvtKindUInt, cvtScalarFlag), SrcWidth: 64, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTSD2USIL", Family: asm.FamilyFP, SubOp: cvtSub(cvtKindFP, cvtKindUInt, cvtScalarFlag), SrcWidth: 64, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTSD2USIQ", Family: asm.FamilyFP, SubOp: cvtSub(cvtKindFP, cvtKindUInt, cvtScalarFlag), SrcWidth: 64, Width: 64, Effect: asm.EffectWriteOnly, LLVMOp: "cvt"},
	{Op: "VCVTTSD2SI", Family: asm.FamilyFP, SubOp: cvtSub(cvtKindFP, cvtKindSInt, cvtScalarFlag), SrcWidth: 64, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTTSD2SIQ", Family: asm.FamilyFP, SubOp: cvtSub(cvtKindFP, cvtKindSInt, cvtScalarFlag), SrcWidth: 64, Width: 64, Effect: asm.EffectWriteOnly, LLVMOp: "cvt"},
	{Op: "VCVTTSD2USI", Family: asm.FamilyFP, SubOp: cvtSub(cvtKindFP, cvtKindUInt, cvtScalarFlag), SrcWidth: 64, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTTSD2USIL", Family: asm.FamilyFP, SubOp: cvtSub(cvtKindFP, cvtKindUInt, cvtScalarFlag), SrcWidth: 64, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTTSD2USIQ", Family: asm.FamilyFP, SubOp: cvtSub(cvtKindFP, cvtKindUInt, cvtScalarFlag), SrcWidth: 64, Width: 64, Effect: asm.EffectWriteOnly, LLVMOp: "cvt"},
	{Op: "VCVTSS2SI", Family: asm.FamilyFP, SubOp: cvtSub(cvtKindFP, cvtKindSInt, cvtScalarFlag), SrcWidth: 32, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTSS2SIQ", Family: asm.FamilyFP, SubOp: cvtSub(cvtKindFP, cvtKindSInt, cvtScalarFlag), SrcWidth: 32, Width: 64, Effect: asm.EffectWriteOnly, LLVMOp: "cvt"},
	{Op: "VCVTSS2USI", Family: asm.FamilyFP, SubOp: cvtSub(cvtKindFP, cvtKindUInt, cvtScalarFlag), SrcWidth: 32, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTSS2USIL", Family: asm.FamilyFP, SubOp: cvtSub(cvtKindFP, cvtKindUInt, cvtScalarFlag), SrcWidth: 32, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTSS2USIQ", Family: asm.FamilyFP, SubOp: cvtSub(cvtKindFP, cvtKindUInt, cvtScalarFlag), SrcWidth: 32, Width: 64, Effect: asm.EffectWriteOnly, LLVMOp: "cvt"},
	{Op: "VCVTTSS2SI", Family: asm.FamilyFP, SubOp: cvtSub(cvtKindFP, cvtKindSInt, cvtScalarFlag), SrcWidth: 32, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTTSS2SIQ", Family: asm.FamilyFP, SubOp: cvtSub(cvtKindFP, cvtKindSInt, cvtScalarFlag), SrcWidth: 32, Width: 64, Effect: asm.EffectWriteOnly, LLVMOp: "cvt"},
	{Op: "VCVTTSS2USI", Family: asm.FamilyFP, SubOp: cvtSub(cvtKindFP, cvtKindUInt, cvtScalarFlag), SrcWidth: 32, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTTSS2USIL", Family: asm.FamilyFP, SubOp: cvtSub(cvtKindFP, cvtKindUInt, cvtScalarFlag), SrcWidth: 32, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTTSS2USIQ", Family: asm.FamilyFP, SubOp: cvtSub(cvtKindFP, cvtKindUInt, cvtScalarFlag), SrcWidth: 32, Width: 64, Effect: asm.EffectWriteOnly, LLVMOp: "cvt"},

	{Op: "VCVTUSI2SD", Family: asm.FamilyFP, SubOp: cvtSub(cvtKindUInt, cvtKindFP, cvtScalarFlag), SrcWidth: 32, Width: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTUSI2SDL", Family: asm.FamilyFP, SubOp: cvtSub(cvtKindUInt, cvtKindFP, cvtScalarFlag), SrcWidth: 32, Width: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTUSI2SDQ", Family: asm.FamilyFP, SubOp: cvtSub(cvtKindUInt, cvtKindFP, cvtScalarFlag), SrcWidth: 64, Width: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTUSI2SS", Family: asm.FamilyFP, SubOp: cvtSub(cvtKindUInt, cvtKindFP, cvtScalarFlag), SrcWidth: 32, Width: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTUSI2SSL", Family: asm.FamilyFP, SubOp: cvtSub(cvtKindUInt, cvtKindFP, cvtScalarFlag), SrcWidth: 32, Width: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
	{Op: "VCVTUSI2SSQ", Family: asm.FamilyFP, SubOp: cvtSub(cvtKindUInt, cvtKindFP, cvtScalarFlag), SrcWidth: 64, Width: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cvt"},
}

var x86M2FMACVTTable = asm.NewOpTable(x86M2FMACVTSpecs)

func (c *amd64Ctx) lowerM2FMACVT(op asm.Op, ins asm.Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(ins.Op))
	zeroMask := strings.Contains(rawOp, ".Z")
	bcst := strings.Contains(rawOp, ".BCST")
	baseOp := op
	if dot := strings.IndexByte(string(baseOp), '.'); dot >= 0 {
		baseOp = asm.Op(string(baseOp)[:dot])
	}
	spec, found := x86M2FMACVTTable.Lookup(baseOp)
	if !found {
		return false, false, nil
	}
	if spec.Family == asm.FamilyVecFMA {
		return true, false, c.lowerX86FMA(spec, zeroMask, bcst, ins)
	}
	return true, false, c.lowerX86CVT(spec, zeroMask, bcst, ins)
}

func x86Expand4RegGroup(op asm.Operand) []asm.Reg {
	if op.Kind == asm.OpRegList && len(op.RegList) > 0 {
		return op.RegList
	}
	if op.Kind == asm.OpReg {
		s := strings.ToUpper(string(op.Reg))
		if len(s) >= 2 && (s[0] == 'Z' || s[0] == 'Y' || s[0] == 'X') {
			if idx, ok := amd64ParseZReg(op.Reg); ok {
				return []asm.Reg{
					asm.Reg(fmt.Sprintf("Z%d", idx)),
					asm.Reg(fmt.Sprintf("Z%d", (idx+1)&31)),
					asm.Reg(fmt.Sprintf("Z%d", (idx+2)&31)),
					asm.Reg(fmt.Sprintf("Z%d", (idx+3)&31)),
				}
			}
			if idx, ok := amd64ParseXReg(op.Reg); ok {
				return []asm.Reg{
					asm.Reg(fmt.Sprintf("X%d", idx)),
					asm.Reg(fmt.Sprintf("X%d", (idx+1)&31)),
					asm.Reg(fmt.Sprintf("X%d", (idx+2)&31)),
					asm.Reg(fmt.Sprintf("X%d", (idx+3)&31)),
				}
			}
		}
	}
	return nil
}

func (c *amd64Ctx) lowerX86FMA(spec asm.OpSpec, zeroMask, bcst bool, ins asm.Instr) error {
	args, kreg, hasMask := x86StripEVEXMask(ins.Args)
	if len(args) != 3 || args[2].Kind != asm.OpReg {
		return fmt.Errorf("amd64 %s expects src3, src2, [K,] dst: %q", spec.Op, ins.Raw)
	}
	mode := spec.SubOp & 0xf
	order := spec.SubOp & 0xf0
	isScalar := (spec.SubOp & fmaScalarFlag) != 0

	// 4FMA: V4FMADDPS/SS, V4FNMADDPS/SS mem128, [Z0-Z3]/[X0-X3] or Z0/X0, [K,] dst
	if order == fmaOrder4x {
		regList := x86Expand4RegGroup(args[1])
		if len(regList) == 0 {
			return fmt.Errorf("amd64 %s expects mem, [reg-list], [K,] dst: %q", spec.Op, ins.Raw)
		}
		var memPtr, memPtrTy string
		var err error
		switch args[0].Kind {
		case asm.OpMem:
			memPtr, memPtrTy, err = c.ptrFromMem(args[0].Mem)
		case asm.OpSym:
			memPtr, err = c.ptrFromSB(args[0].Sym)
			memPtrTy = "ptr"
		default:
			return fmt.Errorf("amd64 %s expects memory first operand: %q", spec.Op, ins.Raw)
		}
		if err != nil {
			return err
		}
		ld4 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load <4 x float>, %s %s, align 1\n", ld4, memPtrTy, memPtr)
		if isScalar {
			acc, err := c.loadXLowF32(args[2].Reg)
			if err != nil {
				return err
			}
			oldAcc := acc
			for i, r := range regList {
				if i >= 4 {
					break
				}
				rv, err := c.loadXLowF32(r)
				if err != nil {
					return err
				}
				mv := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = extractelement <4 x float> %%%s, i32 %d\n", mv, ld4, i)
				aVal := rv
				if mode == fmaModeNAdd {
					neg := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = fneg float %s\n", neg, rv)
					aVal = "%" + neg
				}
				nxt := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = call float @llvm.fma.f32(float %s, float %%%s, float %s)\n", nxt, aVal, mv, acc)
				acc = "%" + nxt
			}
			if hasMask {
				acc, err = c.x86ApplyScalarMask(kreg, zeroMask, "float", acc, oldAcc)
				if err != nil {
					return err
				}
			}
			return c.storeXLowF32(args[2].Reg, acc)
		}
		vi, ok := c.x86VecInfoForReg(args[2].Reg)
		if !ok {
			return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
		}
		lanes := vi.totalBits / 32
		vecTy := fmt.Sprintf("<%d x float>", lanes)
		intr := fmt.Sprintf("@llvm.fma.v%df32", lanes)
		oldBytes, err := vi.loadReg(args[2].Reg)
		if err != nil {
			return err
		}
		accBC := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", accBC, vi.byteVecTy, oldBytes, vecTy)
		acc := "%" + accBC
		oldF := acc
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
			rf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", rf, vi.byteVecTy, rb, vecTy)
			sc, splat0, splat := c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <4 x float> %%%s, i32 %d\n", sc, ld4, i)
			fmt.Fprintf(c.b, "  %%%s = insertelement %s undef, float %%%s, i32 0\n", splat0, vecTy, sc)
			fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <%d x i32> zeroinitializer\n", splat, vecTy, splat0, vecTy, lanes)
			aVal := "%" + rf
			if mode == fmaModeNAdd {
				neg := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", neg, vecTy, aVal)
				aVal = "%" + neg
			}
			nxt := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call %s %s(%s %s, %s %%%s, %s %s)\n", nxt, vecTy, intr, vecTy, aVal, vecTy, splat, vecTy, acc)
			acc = "%" + nxt
		}
		if hasMask {
			acc, err = c.x86ApplyMask(kreg, zeroMask, lanes, vecTy, acc, oldF)
			if err != nil {
				return err
			}
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, vecTy, acc, vi.byteVecTy)
		return vi.storeVec(args[2].Reg, "%"+out)
	}

	// Scalar FMA3 (*SS / *SD)
	if isScalar {
		if !isAMD64XReg(args[2].Reg) {
			return fmt.Errorf("amd64 %s expects X dst: %q", spec.Op, ins.Raw)
		}
		isF32 := spec.LaneBits == 32
		fpTy, intr := "double", "@llvm.fma.f64"
		if isF32 {
			fpTy, intr = "float", "@llvm.fma.f32"
		}
		evalS := c.evalF64
		loadS := c.loadXLowF64
		storeS := c.storeXLowF64
		if isF32 {
			evalS = c.evalF32
			loadS = c.loadXLowF32
			storeS = c.storeXLowF32
		}
		op3, err := evalS(args[0])
		if err != nil {
			return err
		}
		op2, err := evalS(args[1])
		if err != nil {
			return err
		}
		op1, err := loadS(args[2].Reg)
		if err != nil {
			return err
		}
		a, b, cv := x86FMASelectOperands(order, op1, op2, op3)
		res := c.emitX86FMAOp(mode, 1, fpTy, intr, a, b, cv)
		if hasMask {
			res, err = c.x86ApplyScalarMask(kreg, zeroMask, fpTy, res, op1)
			if err != nil {
				return err
			}
		}
		return storeS(args[2].Reg, res)
	}

	// Packed FMA3 (*PS / *PD) across X/Y/Z
	vi, ok := c.x86VecInfoForReg(args[2].Reg)
	if !ok {
		return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
	}
	laneBits := int(spec.LaneBits)
	lanes := vi.totalBits / laneBits
	elemTy := "double"
	intrSuf := "f64"
	if laneBits == 32 {
		elemTy = "float"
		intrSuf = "f32"
	}
	vecTy := fmt.Sprintf("<%d x %s>", lanes, elemTy)
	intr := fmt.Sprintf("@llvm.fma.v%d%s", lanes, intrSuf)

	raw3, err := c.x86LoadVecOrBcst(vi, args[0], bcst, laneBits)
	if err != nil {
		return err
	}
	raw2, err := vi.loadVec(args[1])
	if err != nil {
		return err
	}
	raw1, err := vi.loadReg(args[2].Reg)
	if err != nil {
		return err
	}
	b1, b2, b3 := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", b1, vi.byteVecTy, raw1, vecTy)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", b2, vi.byteVecTy, raw2, vecTy)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", b3, vi.byteVecTy, raw3, vecTy)
	a, b, cv := x86FMASelectOperands(order, "%"+b1, "%"+b2, "%"+b3)
	res := c.emitX86FMAOp(mode, lanes, vecTy, intr, a, b, cv)
	if hasMask {
		res, err = c.x86ApplyMask(kreg, zeroMask, lanes, vecTy, res, "%"+b1)
		if err != nil {
			return err
		}
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, vecTy, res, vi.byteVecTy)
	return vi.storeVec(args[2].Reg, "%"+out)
}

func x86FMASelectOperands(order uint16, op1, op2, op3 string) (a, b, c string) {
	switch order {
	case fmaOrder132:
		return op1, op3, op2
	case fmaOrder213:
		return op2, op1, op3
	default: // 231
		return op2, op3, op1
	}
}

func (c *amd64Ctx) emitX86FMAOp(mode uint16, lanes int, ty, intr, a, b, cv string) string {
	switch mode {
	case fmaModeAdd:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s %s(%s %s, %s %s, %s %s)\n", t, ty, intr, ty, a, ty, b, ty, cv)
		return "%" + t
	case fmaModeSub:
		nc, t := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", nc, ty, cv)
		fmt.Fprintf(c.b, "  %%%s = call %s %s(%s %s, %s %s, %s %%%s)\n", t, ty, intr, ty, a, ty, b, ty, nc)
		return "%" + t
	case fmaModeNAdd:
		na, t := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", na, ty, a)
		fmt.Fprintf(c.b, "  %%%s = call %s %s(%s %%%s, %s %s, %s %s)\n", t, ty, intr, ty, na, ty, b, ty, cv)
		return "%" + t
	case fmaModeNSub:
		na, nc, t := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", na, ty, a)
		fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", nc, ty, cv)
		fmt.Fprintf(c.b, "  %%%s = call %s %s(%s %%%s, %s %s, %s %%%s)\n", t, ty, intr, ty, na, ty, b, ty, nc)
		return "%" + t
	default:
		// FMADDSUB (odd add, even sub) / FMSUBADD (odd sub, even add)
		addv, nc, subv, sel := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s %s(%s %s, %s %s, %s %s)\n", addv, ty, intr, ty, a, ty, b, ty, cv)
		fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", nc, ty, cv)
		fmt.Fprintf(c.b, "  %%%s = call %s %s(%s %s, %s %s, %s %%%s)\n", subv, ty, intr, ty, a, ty, b, ty, nc)
		maskBits := make([]string, lanes)
		for i := 0; i < lanes; i++ {
			pickAdd := (i%2 == 1)
			if mode == fmaModeSubAdd {
				pickAdd = !pickAdd
			}
			if pickAdd {
				maskBits[i] = "i1 true"
			} else {
				maskBits[i] = "i1 false"
			}
		}
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> <%s>, %s %%%s, %s %%%s\n",
			sel, lanes, strings.Join(maskBits, ", "), ty, addv, ty, subv)
		return "%" + sel
	}
}

func (c *amd64Ctx) x86ApplyScalarMask(kreg asm.Reg, zeroMask bool, fpTy, resVal, oldVal string) (string, error) {
	kv, err := c.loadK(kreg)
	if err != nil {
		return "", err
	}
	bit, sel := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i1\n", bit, kv)
	fb := oldVal
	if zeroMask {
		fb = "0.0"
	}
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %s, %s %s\n", sel, bit, fpTy, resVal, fpTy, fb)
	return "%" + sel, nil
}

func x86CVTElemType(kind uint16, bits int) string {
	switch kind {
	case cvtKindFP:
		if bits == 32 {
			return "float"
		}
		return "double"
	case cvtKindFP16:
		return "half"
	default:
		return fmt.Sprintf("i%d", bits)
	}
}

func x86CVTLLVMOp(srcKind uint16, srcBits int, dstKind uint16, dstBits int) string {
	switch {
	case (srcKind == cvtKindFP || srcKind == cvtKindFP16) && (dstKind == cvtKindFP || dstKind == cvtKindFP16):
		if dstBits > srcBits {
			return "fpext"
		}
		return "fptrunc"
	case (srcKind == cvtKindFP || srcKind == cvtKindFP16) && dstKind == cvtKindSInt:
		return "fptosi"
	case (srcKind == cvtKindFP || srcKind == cvtKindFP16) && dstKind == cvtKindUInt:
		return "fptoui"
	case srcKind == cvtKindSInt && (dstKind == cvtKindFP || dstKind == cvtKindFP16):
		return "sitofp"
	case srcKind == cvtKindUInt && (dstKind == cvtKindFP || dstKind == cvtKindFP16):
		return "uitofp"
	default:
		return "bitcast"
	}
}

func (c *amd64Ctx) lowerX86CVT(spec asm.OpSpec, zeroMask, bcst bool, ins asm.Instr) error {
	srcKind := spec.SubOp & 0xf
	dstKind := (spec.SubOp >> 4) & 0xf
	isScalar := (spec.SubOp & cvtScalarFlag) != 0
	hasImm := (spec.SubOp & cvtImmFlag) != 0
	srcBits := int(spec.SrcWidth)
	dstBits := int(spec.Width)
	srcElemTy := x86CVTElemType(srcKind, srcBits)
	dstElemTy := x86CVTElemType(dstKind, dstBits)
	cvtOp := x86CVTLLVMOp(srcKind, srcBits, dstKind, dstBits)

	// Scalar conversions (VCVT*SS/SD <-> GPR)
	if isScalar {
		if spec.ThreeOp {
			// VCVTUSI2{SS,SD}{L,Q} intSrc, Xsrc2, Xdst
			if len(ins.Args) != 3 || ins.Args[2].Kind != asm.OpReg || !isAMD64XReg(ins.Args[2].Reg) {
				return fmt.Errorf("amd64 %s expects srcInt, Xsrc2, Xdst: %q", spec.Op, ins.Raw)
			}
			intTy := x86LLVMIntType(uint16(srcBits))
			iv, err := c.evalIntSized(ins.Args[0], intTy)
			if err != nil {
				return err
			}
			// Copy upper lanes from Xsrc2 into Xdst before inserting lane 0.
			x2, err := c.loadXVecOperand(ins.Args[1])
			if err != nil {
				return err
			}
			if err := c.storeX(ins.Args[2].Reg, x2); err != nil {
				return err
			}
			fv := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", fv, cvtOp, intTy, iv, dstElemTy)
			if dstBits == 32 {
				return c.storeXLowF32(ins.Args[2].Reg, "%"+fv)
			}
			return c.storeXLowF64(ins.Args[2].Reg, "%"+fv)
		}
		// 2-op: VCVT[T]{SS,SD}2[U]SI[L,Q] srcFP, dstGPR
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects srcFP, dstReg: %q", spec.Op, ins.Raw)
		}
		var fv string
		var err error
		if srcBits == 32 {
			fv, err = c.evalF32(ins.Args[0])
		} else {
			fv, err = c.evalF64(ins.Args[0])
		}
		if err != nil {
			return err
		}
		iv := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", iv, cvtOp, srcElemTy, fv, dstElemTy)
		if dstBits == 32 {
			return c.storeRegSized(ins.Args[1].Reg, asm.I32, "%"+iv)
		}
		return c.storeReg(ins.Args[1].Reg, "%"+iv)
	}

	// Packed conversions (same-width, widening 1:2, narrowing 2:1, FP16)
	args, kreg, hasMask := x86StripEVEXMask(ins.Args)
	if hasImm {
		if len(args) != 3 || args[0].Kind != asm.OpImm {
			return fmt.Errorf("amd64 %s expects $imm, src, [K,] dst: %q", spec.Op, ins.Raw)
		}
		args = args[1:]
	} else if len(args) != 2 {
		return fmt.Errorf("amd64 %s expects src, [K,] dst: %q", spec.Op, ins.Raw)
	}
	srcOp, dstOp := args[0], args[1]

	// Determine lane count and destination vector info (if dst is a vector reg).
	var dstVI x86VecInfo
	dstIsReg := dstOp.Kind == asm.OpReg
	if dstIsReg {
		var ok bool
		dstVI, ok = c.x86VecInfoForReg(dstOp.Reg)
		if !ok {
			return fmt.Errorf("amd64 %s dst must be vector reg: %q", spec.Op, ins.Raw)
		}
	}

	var lanes int
	switch {
	case dstBits > srcBits:
		// Widening (e.g. VCVTDQ2PD, VCVTPS2PD, VCVTPH2PS, VCVTPS2QQ): dst is full vector
		if !dstIsReg {
			return fmt.Errorf("amd64 %s requires vector register dst: %q", spec.Op, ins.Raw)
		}
		lanes = dstVI.totalBits / dstBits
	case dstBits == srcBits:
		// Same width (e.g. VCVTDQ2PS, VCVTPS2DQ, VCVTPD2QQ)
		if !dstIsReg {
			return fmt.Errorf("amd64 %s requires vector register dst: %q", spec.Op, ins.Raw)
		}
		lanes = dstVI.totalBits / dstBits
	default:
		// Narrowing (e.g. VCVTPD2DQ, VCVTPD2PS, VCVTQQ2PS, VCVTPS2PH):
		// Infer lane count from src reg, or explicit X/Y suffix, or dst reg width.
		if srcOp.Kind == asm.OpReg {
			svi, ok := c.x86VecInfoForReg(srcOp.Reg)
			if !ok {
				return fmt.Errorf("amd64 %s invalid src reg %s: %q", spec.Op, srcOp.Reg, ins.Raw)
			}
			lanes = svi.totalBits / srcBits
		} else if (spec.SubOp & cvtMem128Flag) != 0 {
			lanes = 128 / srcBits
		} else if (spec.SubOp & cvtMem256Flag) != 0 {
			lanes = 256 / srcBits
		} else if dstIsReg {
			// When src is memory without X/Y suffix (e.g. VCVTPD2DQ (BX), Y2 -> ZMM mem -> 8 lanes;
			// VCVTPD2DQ (BX), X2 -> XMM/YMM mem -> 4 lanes if dst is 128b).
			lanes = dstVI.totalBits / dstBits
		} else {
			lanes = 128 / srcBits
		}
	}

	srcVecTy := fmt.Sprintf("<%d x %s>", lanes, srcElemTy)
	dstVecTy := fmt.Sprintf("<%d x %s>", lanes, dstElemTy)

	// Load `lanes` elements of `srcElemTy` from srcOp (supporting reg, partial reg, mem, .BCST, sym).
	srcVal, err := c.x86LoadTypedLanes(srcOp, lanes, srcBits, srcElemTy, bcst)
	if err != nil {
		return err
	}

	// Emit conversion.
	conv := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", conv, cvtOp, srcVecTy, srcVal, dstVecTy)
	res := "%" + conv

	// Store to memory (only VCVTPS2PH supports memory dst).
	if !dstIsReg {
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
			mvec, err := c.x86KToI1Vec(kreg, lanes)
			if err != nil {
				return err
			}
			mangle := x86LLVMVecMangle(lanes, dstKind, dstBits)
			fmt.Fprintf(c.b, "  call void @llvm.masked.store.%s.p0(%s %s, %s %s, i32 1, <%d x i1> %s)\n",
				mangle, dstVecTy, res, pty, p, lanes, mvec)
			return nil
		}
		fmt.Fprintf(c.b, "  store %s %s, %s %s, align 1\n", dstVecTy, res, pty, p)
		return nil
	}

	// Store to vector register dstVI (possibly narrower than dstVI.totalBits, zero-extended in upper lanes).
	dstFullLanes := dstVI.totalBits / dstBits
	dstFullTy := fmt.Sprintf("<%d x %s>", dstFullLanes, dstElemTy)
	if hasMask {
		oldBytes, err := dstVI.loadReg(dstOp.Reg)
		if err != nil {
			return err
		}
		oldFull := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", oldFull, dstVI.byteVecTy, oldBytes, dstFullTy)
		oldNarrow := "%" + oldFull
		if lanes < dstFullLanes {
			sh := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s zeroinitializer, <%d x i32> %s\n",
				sh, dstFullTy, oldFull, dstFullTy, lanes, llvmI32RangeMask(0, lanes))
			oldNarrow = "%" + sh
		}
		res, err = c.x86ApplyMask(kreg, zeroMask, lanes, dstVecTy, res, oldNarrow)
		if err != nil {
			return err
		}
	}
	if lanes < dstFullLanes {
		// Zero-extend narrow result vector into full destination register width.
		pad := c.newTmp()
		maskElems := make([]string, dstFullLanes)
		for i := 0; i < dstFullLanes; i++ {
			if i < lanes {
				maskElems[i] = fmt.Sprintf("i32 %d", i)
			} else {
				maskElems[i] = fmt.Sprintf("i32 %d", lanes)
			}
		}
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s zeroinitializer, <%d x i32> <%s>\n",
			pad, dstVecTy, res, dstVecTy, dstFullLanes, strings.Join(maskElems, ", "))
		res = "%" + pad
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", out, dstFullTy, res, dstVI.byteVecTy)
	return dstVI.storeVec(dstOp.Reg, "%"+out)
}

func (c *amd64Ctx) x86LoadTypedLanes(op asm.Operand, lanes, elemBits int, elemTy string, bcst bool) (string, error) {
	vecTy := fmt.Sprintf("<%d x %s>", lanes, elemTy)
	if bcst && (op.Kind == asm.OpMem || op.Kind == asm.OpSym) {
		var p, pty string
		var err error
		if op.Kind == asm.OpMem {
			p, pty, err = c.ptrFromMem(op.Mem)
		} else {
			p, err = c.ptrFromSB(op.Sym)
			pty = "ptr"
		}
		if err != nil {
			return "", err
		}
		ld, ins0, splat := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load %s, %s %s, align 1\n", ld, elemTy, pty, p)
		fmt.Fprintf(c.b, "  %%%s = insertelement %s undef, %s %%%s, i32 0\n", ins0, vecTy, elemTy, ld)
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <%d x i32> zeroinitializer\n", splat, vecTy, ins0, vecTy, lanes)
		return "%" + splat, nil
	}
	switch op.Kind {
	case asm.OpReg:
		svi, ok := c.x86VecInfoForReg(op.Reg)
		if !ok {
			return "", fmt.Errorf("amd64: expected vector reg operand, got %s", op.Reg)
		}
		raw, err := svi.loadReg(op.Reg)
		if err != nil {
			return "", err
		}
		srcFullLanes := svi.totalBits / elemBits
		srcFullTy := fmt.Sprintf("<%d x %s>", srcFullLanes, elemTy)
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bc, svi.byteVecTy, raw, srcFullTy)
		if srcFullLanes == lanes {
			return "%" + bc, nil
		}
		sh := c.newTmp()
		maskElems := make([]string, lanes)
		for i := 0; i < lanes; i++ {
			if i < srcFullLanes {
				maskElems[i] = fmt.Sprintf("i32 %d", i)
			} else {
				maskElems[i] = fmt.Sprintf("i32 %d", srcFullLanes)
			}
		}
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s zeroinitializer, <%d x i32> <%s>\n",
			sh, srcFullTy, bc, srcFullTy, lanes, strings.Join(maskElems, ", "))
		return "%" + sh, nil
	case asm.OpMem:
		p, pty, err := c.ptrFromMem(op.Mem)
		if err != nil {
			return "", err
		}
		ld := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load %s, %s %s, align 1\n", ld, vecTy, pty, p)
		return "%" + ld, nil
	case asm.OpSym:
		p, err := c.ptrFromSB(op.Sym)
		if err != nil {
			return "", err
		}
		ld := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s, align 1\n", ld, vecTy, p)
		return "%" + ld, nil
	default:
		return "", fmt.Errorf("amd64: unsupported vector operand %s", op.String())
	}
}

func (c *amd64Ctx) x86KToI1Vec(kreg asm.Reg, lanes int) (string, error) {
	kv, err := c.loadK(kreg)
	if err != nil {
		return "", err
	}
	maskBits := kv
	if lanes < 64 {
		tr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", tr, kv, lanes)
		maskBits = "%" + tr
	}
	mv := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast i%d %s to <%d x i1>\n", mv, lanes, maskBits, lanes)
	return "%" + mv, nil
}

func (c *amd64Ctx) x86PackI1VecToK(cmpVec string, lanes int) string {
	bc := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i1> %s to i%d\n", bc, lanes, cmpVec, lanes)
	if lanes == 64 {
		return "%" + bc
	}
	z := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i%d %%%s to i64\n", z, lanes, bc)
	return "%" + z
}

func x86LLVMVecMangle(lanes int, kind uint16, bits int) string {
	switch kind {
	case cvtKindFP:
		return fmt.Sprintf("v%df%d", lanes, bits)
	case cvtKindFP16:
		return fmt.Sprintf("v%df16", lanes)
	default:
		return fmt.Sprintf("v%di%d", lanes, bits)
	}
}
