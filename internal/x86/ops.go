package x86

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// OpTable is the declarative x86/amd64 instruction table modeled after Go's
// cmd/internal/obj/x86 optab, targeting LLVM IR lowering and ABI0 effect analysis.
// Adding a new packed integer/FP SIMD binary op only requires adding one row here.
var OpTable = asm.NewOpTable(
	x86ScalarSpecs,
	x86BranchAndSystemSpecs,
	x86VecBinOpSpecs,
	x86VecOtherSpecs,
	x86ExtraScalarSpecs,
	x86ExtraSIMDSpecs,
	x86M2FMACVTSpecs,
	x86M2VecExtSpecs,
	x86M3TailSpecs,
)

var x86ScalarSpecs = []asm.OpSpec{
	// Moves (WriteOnly on dst)
	{Op: "MOVB", Family: asm.FamilyMove, Width: 8, Effect: asm.EffectWriteOnly},
	{Op: "MOVW", Family: asm.FamilyMove, Width: 16, Effect: asm.EffectWriteOnly},
	{Op: "MOVL", Family: asm.FamilyMove, Width: 32, Effect: asm.EffectWriteZeroUpper},
	{Op: "MOVQ", Family: asm.FamilyMove, Width: 64, Effect: asm.EffectWriteOnly},
	{Op: "MOVBLZX", Family: asm.FamilyMove, Width: 32, Effect: asm.EffectWriteZeroUpper},
	{Op: "MOVBQZX", Family: asm.FamilyMove, Width: 64, Effect: asm.EffectWriteOnly},
	{Op: "MOVWLZX", Family: asm.FamilyMove, Width: 32, Effect: asm.EffectWriteZeroUpper},
	{Op: "MOVWQZX", Family: asm.FamilyMove, Width: 64, Effect: asm.EffectWriteOnly},
	{Op: "MOVLQZX", Family: asm.FamilyMove, Width: 64, Effect: asm.EffectWriteOnly},
	{Op: "MOVBLSX", Family: asm.FamilyMove, Width: 32, Signed: true, Effect: asm.EffectWriteZeroUpper},
	{Op: "MOVBQSX", Family: asm.FamilyMove, Width: 64, Signed: true, Effect: asm.EffectWriteOnly},
	{Op: "MOVWLSX", Family: asm.FamilyMove, Width: 32, Signed: true, Effect: asm.EffectWriteZeroUpper},
	{Op: "MOVWQSX", Family: asm.FamilyMove, Width: 64, Signed: true, Effect: asm.EffectWriteOnly},
	{Op: "MOVLQSX", Family: asm.FamilyMove, Width: 64, Signed: true, Effect: asm.EffectWriteOnly},
	{Op: "LEAL", Family: asm.FamilyMove, Width: 32, Effect: asm.EffectWriteZeroUpper},
	{Op: "LEAQ", Family: asm.FamilyMove, Width: 64, Effect: asm.EffectWriteOnly},

	// Scalar ALU (ReadWrite on dst, writes flags)
	{Op: "ADDB", Family: asm.FamilyALU, Width: 8, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "add"},
	{Op: "ADDW", Family: asm.FamilyALU, Width: 16, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "add"},
	{Op: "ADDL", Family: asm.FamilyALU, Width: 32, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "add"},
	{Op: "ADDQ", Family: asm.FamilyALU, Width: 64, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "add"},
	{Op: "SUBB", Family: asm.FamilyALU, Width: 8, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "sub"},
	{Op: "SUBW", Family: asm.FamilyALU, Width: 16, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "sub"},
	{Op: "SUBL", Family: asm.FamilyALU, Width: 32, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "sub"},
	{Op: "SUBQ", Family: asm.FamilyALU, Width: 64, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "sub"},
	{Op: "ADCB", Family: asm.FamilyALU, Width: 8, Effect: asm.EffectReadWrite, Flags: asm.FlagsReadWrite},
	{Op: "ADCL", Family: asm.FamilyALU, Width: 32, Effect: asm.EffectReadWrite, Flags: asm.FlagsReadWrite},
	{Op: "ADCQ", Family: asm.FamilyALU, Width: 64, Effect: asm.EffectReadWrite, Flags: asm.FlagsReadWrite},
	{Op: "SBBB", Family: asm.FamilyALU, Width: 8, Effect: asm.EffectReadWrite, Flags: asm.FlagsReadWrite},
	{Op: "SBBL", Family: asm.FamilyALU, Width: 32, Effect: asm.EffectReadWrite, Flags: asm.FlagsReadWrite},
	{Op: "SBBQ", Family: asm.FamilyALU, Width: 64, Effect: asm.EffectReadWrite, Flags: asm.FlagsReadWrite},
	{Op: "ANDB", Family: asm.FamilyALU, Width: 8, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "and"},
	{Op: "ANDW", Family: asm.FamilyALU, Width: 16, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "and"},
	{Op: "ANDL", Family: asm.FamilyALU, Width: 32, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "and"},
	{Op: "ANDQ", Family: asm.FamilyALU, Width: 64, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "and"},
	{Op: "ORB", Family: asm.FamilyALU, Width: 8, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "or"},
	{Op: "ORW", Family: asm.FamilyALU, Width: 16, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "or"},
	{Op: "ORL", Family: asm.FamilyALU, Width: 32, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "or"},
	{Op: "ORQ", Family: asm.FamilyALU, Width: 64, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "or"},
	{Op: "XORB", Family: asm.FamilyALU, Width: 8, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "xor"},
	{Op: "XORW", Family: asm.FamilyALU, Width: 16, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "xor"},
	{Op: "XORL", Family: asm.FamilyALU, Width: 32, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "xor"},
	{Op: "XORQ", Family: asm.FamilyALU, Width: 64, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "xor"},
	{Op: "INCQ", Family: asm.FamilyALU, Width: 64, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite},
	{Op: "INCL", Family: asm.FamilyALU, Width: 32, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite},
	{Op: "DECQ", Family: asm.FamilyALU, Width: 64, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite},
	{Op: "DECL", Family: asm.FamilyALU, Width: 32, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite},
	{Op: "NEGQ", Family: asm.FamilyALU, Width: 64, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite},
	{Op: "NEGL", Family: asm.FamilyALU, Width: 32, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite},
	{Op: "NOTQ", Family: asm.FamilyALU, Width: 64, Effect: asm.EffectReadWrite},
	{Op: "NOTL", Family: asm.FamilyALU, Width: 32, Effect: asm.EffectReadWrite},

	// Shifts & Bit ops
	{Op: "SHLB", Family: asm.FamilyShift, Width: 8, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite},
	{Op: "SHLW", Family: asm.FamilyShift, Width: 16, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite},
	{Op: "SHLL", Family: asm.FamilyShift, Width: 32, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite},
	{Op: "SHLQ", Family: asm.FamilyShift, Width: 64, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite},
	{Op: "SHRB", Family: asm.FamilyShift, Width: 8, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite},
	{Op: "SHRW", Family: asm.FamilyShift, Width: 16, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite},
	{Op: "SHRL", Family: asm.FamilyShift, Width: 32, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite},
	{Op: "SHRQ", Family: asm.FamilyShift, Width: 64, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite},
	{Op: "SARL", Family: asm.FamilyShift, Width: 32, Signed: true, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite},
	{Op: "SARQ", Family: asm.FamilyShift, Width: 64, Signed: true, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite},
	{Op: "ROLL", Family: asm.FamilyShift, Width: 32, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite},
	{Op: "ROLQ", Family: asm.FamilyShift, Width: 64, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite},
	{Op: "RORL", Family: asm.FamilyShift, Width: 32, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite},
	{Op: "RORQ", Family: asm.FamilyShift, Width: 64, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite},
	{Op: "BSWAPL", Family: asm.FamilyBit, Width: 32, Effect: asm.EffectReadWrite},
	{Op: "BSWAPQ", Family: asm.FamilyBit, Width: 64, Effect: asm.EffectReadWrite},
	{Op: "BSFL", Family: asm.FamilyBit, Width: 32, Effect: asm.EffectWriteZeroUpper, Flags: asm.FlagsWrite},
	{Op: "BSFQ", Family: asm.FamilyBit, Width: 64, Effect: asm.EffectWriteOnly, Flags: asm.FlagsWrite},
	{Op: "BSRL", Family: asm.FamilyBit, Width: 32, Effect: asm.EffectWriteZeroUpper, Flags: asm.FlagsWrite},
	{Op: "BSRQ", Family: asm.FamilyBit, Width: 64, Effect: asm.EffectWriteOnly, Flags: asm.FlagsWrite},
	{Op: "TZCNTL", Family: asm.FamilyBit, Width: 32, Effect: asm.EffectWriteZeroUpper, Flags: asm.FlagsWrite},
	{Op: "TZCNTQ", Family: asm.FamilyBit, Width: 64, Effect: asm.EffectWriteOnly, Flags: asm.FlagsWrite},
	{Op: "LZCNTL", Family: asm.FamilyBit, Width: 32, Effect: asm.EffectWriteZeroUpper, Flags: asm.FlagsWrite},
	{Op: "LZCNTQ", Family: asm.FamilyBit, Width: 64, Effect: asm.EffectWriteOnly, Flags: asm.FlagsWrite},
	{Op: "POPCNTL", Family: asm.FamilyBit, Width: 32, Effect: asm.EffectWriteZeroUpper, Flags: asm.FlagsWrite},
	{Op: "POPCNTQ", Family: asm.FamilyBit, Width: 64, Effect: asm.EffectWriteOnly, Flags: asm.FlagsWrite},

	// Compare / Test (ReadOnly, writes flags)
	{Op: "CMPB", Family: asm.FamilyCompare, Width: 8, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite},
	{Op: "CMPW", Family: asm.FamilyCompare, Width: 16, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite},
	{Op: "CMPL", Family: asm.FamilyCompare, Width: 32, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite},
	{Op: "CMPQ", Family: asm.FamilyCompare, Width: 64, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite},
	{Op: "TESTB", Family: asm.FamilyCompare, Width: 8, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite},
	{Op: "TESTW", Family: asm.FamilyCompare, Width: 16, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite},
	{Op: "TESTL", Family: asm.FamilyCompare, Width: 32, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite},
	{Op: "TESTQ", Family: asm.FamilyCompare, Width: 64, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite},

	// Mul / Div
	{Op: "IMULL", Family: asm.FamilyMulDiv, Width: 32, Signed: true, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite},
	{Op: "IMULQ", Family: asm.FamilyMulDiv, Width: 64, Signed: true, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite},
	{Op: "IMUL3L", Family: asm.FamilyMulDiv, Width: 32, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, Flags: asm.FlagsWrite},
	{Op: "IMUL3Q", Family: asm.FamilyMulDiv, Width: 64, Signed: true, ThreeOp: true, Effect: asm.EffectWriteOnly, Flags: asm.FlagsWrite},
	{Op: "MULL", Family: asm.FamilyMulDiv, Width: 32, Effect: asm.EffectImplicit, Implicit: asm.ImplicitAX | asm.ImplicitDX, Flags: asm.FlagsWrite},
	{Op: "MULQ", Family: asm.FamilyMulDiv, Width: 64, Effect: asm.EffectImplicit, Implicit: asm.ImplicitAX | asm.ImplicitDX, Flags: asm.FlagsWrite},
	{Op: "MULXL", Family: asm.FamilyMulDiv, Width: 32, ThreeOp: true, Effect: asm.EffectImplicit, Implicit: asm.ImplicitDX},
	{Op: "MULXQ", Family: asm.FamilyMulDiv, Width: 64, ThreeOp: true, Effect: asm.EffectImplicit, Implicit: asm.ImplicitDX},
	{Op: "DIVL", Family: asm.FamilyMulDiv, Width: 32, Effect: asm.EffectImplicit, Implicit: asm.ImplicitAX | asm.ImplicitDX, Flags: asm.FlagsClobber},
	{Op: "DIVQ", Family: asm.FamilyMulDiv, Width: 64, Effect: asm.EffectImplicit, Implicit: asm.ImplicitAX | asm.ImplicitDX, Flags: asm.FlagsClobber},
	{Op: "IDIVL", Family: asm.FamilyMulDiv, Width: 32, Signed: true, Effect: asm.EffectImplicit, Implicit: asm.ImplicitAX | asm.ImplicitDX, Flags: asm.FlagsClobber},
	{Op: "IDIVQ", Family: asm.FamilyMulDiv, Width: 64, Signed: true, Effect: asm.EffectImplicit, Implicit: asm.ImplicitAX | asm.ImplicitDX, Flags: asm.FlagsClobber},
}

var x86BranchAndSystemSpecs = []asm.OpSpec{
	{Op: "CALL", Family: asm.FamilyBranch, Effect: asm.EffectImplicit, Implicit: asm.ImplicitAX, Flags: asm.FlagsClobber},
	{Op: "JMP", Family: asm.FamilyBranch, Effect: asm.EffectReadOnly},
	{Op: "RET", Family: asm.FamilyBranch, Effect: asm.EffectReadOnly},
	{Op: "SYSCALL", Family: asm.FamilySyscall, Width: 64, Effect: asm.EffectImplicit, Implicit: asm.ImplicitAX | asm.ImplicitDX | asm.ImplicitCX, Flags: asm.FlagsClobber},
	{Op: "INT", Family: asm.FamilySyscall, Width: 32, Effect: asm.EffectImplicit, Flags: asm.FlagsClobber},
	{Op: "CPUID", Family: asm.FamilySystem, Width: 32, Effect: asm.EffectImplicit, Implicit: asm.ImplicitAX | asm.ImplicitBX | asm.ImplicitCX | asm.ImplicitDX},
	{Op: "XGETBV", Family: asm.FamilySystem, Width: 32, Effect: asm.EffectImplicit, Implicit: asm.ImplicitAX | asm.ImplicitCX | asm.ImplicitDX},
	{Op: "RDTSC", Family: asm.FamilySystem, Width: 32, Effect: asm.EffectImplicit, Implicit: asm.ImplicitAX | asm.ImplicitDX},
	{Op: "RDTSCP", Family: asm.FamilySystem, Width: 32, Effect: asm.EffectImplicit, Implicit: asm.ImplicitAX | asm.ImplicitDX | asm.ImplicitCX},
	{Op: "CQO", Family: asm.FamilyALU, Width: 64, Effect: asm.EffectImplicit, Implicit: asm.ImplicitAX | asm.ImplicitDX},
	{Op: "CDQ", Family: asm.FamilyALU, Width: 32, Effect: asm.EffectImplicit, Implicit: asm.ImplicitAX | asm.ImplicitDX},
	{Op: "CDQE", Family: asm.FamilyALU, Width: 64, Effect: asm.EffectImplicit, Implicit: asm.ImplicitAX},
	{Op: "CWDE", Family: asm.FamilyALU, Width: 32, Effect: asm.EffectImplicit, Implicit: asm.ImplicitAX},
	{Op: "CBW", Family: asm.FamilyALU, Width: 16, Effect: asm.EffectImplicit, Implicit: asm.ImplicitAX},
	{Op: "NOP", Family: asm.FamilyNOP, Effect: asm.EffectNone},
	{Op: "VZEROUPPER", Family: asm.FamilyNOP, Effect: asm.EffectNone},
	{Op: "VZEROALL", Family: asm.FamilyNOP, Effect: asm.EffectImplicit},
}

// x86VecBinOpSpecs declaratively defines packed SIMD binary operations.
// A single emitter (lowerDeclarativeVecBinOp) lowers every row across
// XMM (128-bit), YMM (256-bit), and ZMM (512-bit) widths automatically.
var x86VecBinOpSpecs = []asm.OpSpec{
	// SSE2 legacy 2-operand packed integer ops
	{Op: "PADDB", Family: asm.FamilyVecBinOp, LaneBits: 8, Effect: asm.EffectReadWrite, LLVMOp: "add"},
	{Op: "PADDW", Family: asm.FamilyVecBinOp, LaneBits: 16, Effect: asm.EffectReadWrite, LLVMOp: "add"},
	{Op: "PADDD", Family: asm.FamilyVecBinOp, LaneBits: 32, Effect: asm.EffectReadWrite, LLVMOp: "add"},
	{Op: "PADDL", Family: asm.FamilyVecBinOp, LaneBits: 32, Effect: asm.EffectReadWrite, LLVMOp: "add"},
	{Op: "PADDQ", Family: asm.FamilyVecBinOp, LaneBits: 64, Effect: asm.EffectReadWrite, LLVMOp: "add"},
	{Op: "PSUBB", Family: asm.FamilyVecBinOp, LaneBits: 8, Effect: asm.EffectReadWrite, LLVMOp: "sub"},
	{Op: "PSUBW", Family: asm.FamilyVecBinOp, LaneBits: 16, Effect: asm.EffectReadWrite, LLVMOp: "sub"},
	{Op: "PSUBD", Family: asm.FamilyVecBinOp, LaneBits: 32, Effect: asm.EffectReadWrite, LLVMOp: "sub"},
	{Op: "PSUBL", Family: asm.FamilyVecBinOp, LaneBits: 32, Effect: asm.EffectReadWrite, LLVMOp: "sub"},
	{Op: "PSUBQ", Family: asm.FamilyVecBinOp, LaneBits: 64, Effect: asm.EffectReadWrite, LLVMOp: "sub"},
	{Op: "PMULLW", Family: asm.FamilyVecBinOp, LaneBits: 16, Effect: asm.EffectReadWrite, LLVMOp: "mul"},
	{Op: "PMULLD", Family: asm.FamilyVecBinOp, LaneBits: 32, Effect: asm.EffectReadWrite, LLVMOp: "mul", ArchFeature: "+sse4.1"},
	{Op: "PAND", Family: asm.FamilyVecBinOp, LaneBits: 8, Effect: asm.EffectReadWrite, LLVMOp: "and"},
	{Op: "PANDN", Family: asm.FamilyVecBinOp, LaneBits: 8, Effect: asm.EffectReadWrite, LLVMOp: "andn"},
	{Op: "POR", Family: asm.FamilyVecBinOp, LaneBits: 8, Effect: asm.EffectReadWrite, LLVMOp: "or"},
	{Op: "PXOR", Family: asm.FamilyVecBinOp, LaneBits: 8, Effect: asm.EffectReadWrite, LLVMOp: "xor"},
	{Op: "PMULULQ", Family: asm.FamilyVecBinOp, LaneBits: 64, Effect: asm.EffectReadWrite, LLVMOp: "pmuludq", ArchFeature: "+sse2"},
	{Op: "PMINUB", Family: asm.FamilyVecBinOp, LaneBits: 8, Effect: asm.EffectReadWrite, LLVMOp: "umin"},
	{Op: "PMAXUB", Family: asm.FamilyVecBinOp, LaneBits: 8, Effect: asm.EffectReadWrite, LLVMOp: "umax"},
	{Op: "PMINSB", Family: asm.FamilyVecBinOp, LaneBits: 8, Signed: true, Effect: asm.EffectReadWrite, LLVMOp: "smin", ArchFeature: "+sse4.1"},
	{Op: "PMAXSB", Family: asm.FamilyVecBinOp, LaneBits: 8, Signed: true, Effect: asm.EffectReadWrite, LLVMOp: "smax", ArchFeature: "+sse4.1"},
	{Op: "PMINSW", Family: asm.FamilyVecBinOp, LaneBits: 16, Signed: true, Effect: asm.EffectReadWrite, LLVMOp: "smin"},
	{Op: "PMAXSW", Family: asm.FamilyVecBinOp, LaneBits: 16, Signed: true, Effect: asm.EffectReadWrite, LLVMOp: "smax"},
	{Op: "PMINUW", Family: asm.FamilyVecBinOp, LaneBits: 16, Effect: asm.EffectReadWrite, LLVMOp: "umin", ArchFeature: "+sse4.1"},
	{Op: "PMAXUW", Family: asm.FamilyVecBinOp, LaneBits: 16, Effect: asm.EffectReadWrite, LLVMOp: "umax", ArchFeature: "+sse4.1"},
	{Op: "PMINSD", Family: asm.FamilyVecBinOp, LaneBits: 32, Signed: true, Effect: asm.EffectReadWrite, LLVMOp: "smin", ArchFeature: "+sse4.1"},
	{Op: "PMAXSD", Family: asm.FamilyVecBinOp, LaneBits: 32, Signed: true, Effect: asm.EffectReadWrite, LLVMOp: "smax", ArchFeature: "+sse4.1"},
	{Op: "PMINUD", Family: asm.FamilyVecBinOp, LaneBits: 32, Effect: asm.EffectReadWrite, LLVMOp: "umin", ArchFeature: "+sse4.1"},
	{Op: "PMAXUD", Family: asm.FamilyVecBinOp, LaneBits: 32, Effect: asm.EffectReadWrite, LLVMOp: "umax", ArchFeature: "+sse4.1"},

	// SSE/SSE2 packed FP ops (2-operand)
	{Op: "ADDPS", Family: asm.FamilyVecBinOp, LaneBits: 32, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "fadd"},
	{Op: "SUBPS", Family: asm.FamilyVecBinOp, LaneBits: 32, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "fsub"},
	{Op: "MULPS", Family: asm.FamilyVecBinOp, LaneBits: 32, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "fmul"},
	{Op: "DIVPS", Family: asm.FamilyVecBinOp, LaneBits: 32, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "fdiv"},
	{Op: "ADDPD", Family: asm.FamilyVecBinOp, LaneBits: 64, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "fadd"},
	{Op: "SUBPD", Family: asm.FamilyVecBinOp, LaneBits: 64, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "fsub"},
	{Op: "MULPD", Family: asm.FamilyVecBinOp, LaneBits: 64, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "fmul"},
	{Op: "DIVPD", Family: asm.FamilyVecBinOp, LaneBits: 64, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "fdiv"},
	{Op: "ANDPS", Family: asm.FamilyVecBinOp, LaneBits: 8, Effect: asm.EffectReadWrite, LLVMOp: "and"},
	{Op: "ANDPD", Family: asm.FamilyVecBinOp, LaneBits: 8, Effect: asm.EffectReadWrite, LLVMOp: "and"},
	{Op: "ORPS", Family: asm.FamilyVecBinOp, LaneBits: 8, Effect: asm.EffectReadWrite, LLVMOp: "or"},
	{Op: "ORPD", Family: asm.FamilyVecBinOp, LaneBits: 8, Effect: asm.EffectReadWrite, LLVMOp: "or"},
	{Op: "XORPS", Family: asm.FamilyVecBinOp, LaneBits: 8, Effect: asm.EffectReadWrite, LLVMOp: "xor"},
	{Op: "XORPD", Family: asm.FamilyVecBinOp, LaneBits: 8, Effect: asm.EffectReadWrite, LLVMOp: "xor"},

	// VEX/EVEX 3-operand packed integer ops (XMM/YMM/ZMM, zeroes upper lanes)
	{Op: "VPADDB", Family: asm.FamilyVecBinOp, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "add", ArchFeature: "+avx2"},
	{Op: "VPADDW", Family: asm.FamilyVecBinOp, LaneBits: 16, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "add", ArchFeature: "+avx2"},
	{Op: "VPADDD", Family: asm.FamilyVecBinOp, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "add", ArchFeature: "+avx2"},
	{Op: "VPADDQ", Family: asm.FamilyVecBinOp, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "add", ArchFeature: "+avx2"},
	{Op: "VPSUBB", Family: asm.FamilyVecBinOp, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "sub", ArchFeature: "+avx2"},
	{Op: "VPSUBW", Family: asm.FamilyVecBinOp, LaneBits: 16, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "sub", ArchFeature: "+avx2"},
	{Op: "VPSUBD", Family: asm.FamilyVecBinOp, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "sub", ArchFeature: "+avx2"},
	{Op: "VPSUBQ", Family: asm.FamilyVecBinOp, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "sub", ArchFeature: "+avx2"},
	{Op: "VPMULLW", Family: asm.FamilyVecBinOp, LaneBits: 16, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "mul", ArchFeature: "+avx"},
	{Op: "VPMULLD", Family: asm.FamilyVecBinOp, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "mul", ArchFeature: "+avx"},
	{Op: "PMULUDQ", Family: asm.FamilyVecBinOp, LaneBits: 64, Effect: asm.EffectReadWrite, LLVMOp: "pmuludq", ArchFeature: "+sse2"},
	{Op: "VPMULUDQ", Family: asm.FamilyVecBinOp, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "pmuludq", ArchFeature: "+avx2"},
	{Op: "PMULDQ", Family: asm.FamilyVecBinOp, LaneBits: 64, Signed: true, Effect: asm.EffectReadWrite, LLVMOp: "pmuldq", ArchFeature: "+sse4.1"},
	{Op: "VPMULDQ", Family: asm.FamilyVecBinOp, LaneBits: 64, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "pmuldq", ArchFeature: "+avx2"},
	{Op: "PMULHW", Family: asm.FamilyVecBinOp, LaneBits: 16, Signed: true, Effect: asm.EffectReadWrite, LLVMOp: "pmulhw", ArchFeature: "+sse2"},
	{Op: "VPMULHW", Family: asm.FamilyVecBinOp, LaneBits: 16, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "pmulhw", ArchFeature: "+avx2"},
	{Op: "PMULHUW", Family: asm.FamilyVecBinOp, LaneBits: 16, Effect: asm.EffectReadWrite, LLVMOp: "pmulhuw", ArchFeature: "+sse2"},
	{Op: "VPMULHUW", Family: asm.FamilyVecBinOp, LaneBits: 16, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "pmulhuw", ArchFeature: "+avx2"},
	{Op: "VPAND", Family: asm.FamilyVecBinOp, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "and", ArchFeature: "+avx"},
	{Op: "VPANDD", Family: asm.FamilyVecBinOp, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "and", ArchFeature: "+avx512f"},
	{Op: "VPANDQ", Family: asm.FamilyVecBinOp, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "and", ArchFeature: "+avx512f"},
	{Op: "VPOR", Family: asm.FamilyVecBinOp, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "or", ArchFeature: "+avx"},
	{Op: "VPORD", Family: asm.FamilyVecBinOp, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "or", ArchFeature: "+avx512f"},
	{Op: "VPORQ", Family: asm.FamilyVecBinOp, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "or", ArchFeature: "+avx512f"},
	{Op: "VPXOR", Family: asm.FamilyVecBinOp, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "xor", ArchFeature: "+avx"},
	{Op: "VPXORD", Family: asm.FamilyVecBinOp, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "xor", ArchFeature: "+avx512f"},
	{Op: "VPXORQ", Family: asm.FamilyVecBinOp, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "xor", ArchFeature: "+avx512f"},
	{Op: "VPMINUB", Family: asm.FamilyVecBinOp, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "umin", ArchFeature: "+avx2"},
	{Op: "VPMAXUB", Family: asm.FamilyVecBinOp, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "umax", ArchFeature: "+avx2"},
	{Op: "VPMINSB", Family: asm.FamilyVecBinOp, LaneBits: 8, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "smin", ArchFeature: "+avx2"},
	{Op: "VPMAXSB", Family: asm.FamilyVecBinOp, LaneBits: 8, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "smax", ArchFeature: "+avx2"},
	{Op: "VPMINSW", Family: asm.FamilyVecBinOp, LaneBits: 16, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "smin", ArchFeature: "+avx2"},
	{Op: "VPMAXSW", Family: asm.FamilyVecBinOp, LaneBits: 16, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "smax", ArchFeature: "+avx2"},
	{Op: "VPMINUW", Family: asm.FamilyVecBinOp, LaneBits: 16, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "umin", ArchFeature: "+avx2"},
	{Op: "VPMAXUW", Family: asm.FamilyVecBinOp, LaneBits: 16, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "umax", ArchFeature: "+avx2"},
	{Op: "VPMINSD", Family: asm.FamilyVecBinOp, LaneBits: 32, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "smin", ArchFeature: "+avx2"},
	{Op: "VPMAXSD", Family: asm.FamilyVecBinOp, LaneBits: 32, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "smax", ArchFeature: "+avx2"},
	{Op: "VPMINUD", Family: asm.FamilyVecBinOp, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "umin", ArchFeature: "+avx2"},
	{Op: "VPMAXUD", Family: asm.FamilyVecBinOp, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "umax", ArchFeature: "+avx2"},
	{Op: "VPMINSQ", Family: asm.FamilyVecBinOp, LaneBits: 64, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "smin", ArchFeature: "+avx512f"},
	{Op: "VPMAXSQ", Family: asm.FamilyVecBinOp, LaneBits: 64, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "smax", ArchFeature: "+avx512f"},
	{Op: "VPMINUQ", Family: asm.FamilyVecBinOp, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "umin", ArchFeature: "+avx512f"},
	{Op: "VPMAXUQ", Family: asm.FamilyVecBinOp, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "umax", ArchFeature: "+avx512f"},

	// VEX/EVEX 3-operand packed FP ops
	{Op: "VADDPS", Family: asm.FamilyVecBinOp, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "fadd", ArchFeature: "+avx"},
	{Op: "VSUBPS", Family: asm.FamilyVecBinOp, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "fsub", ArchFeature: "+avx"},
	{Op: "VMULPS", Family: asm.FamilyVecBinOp, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "fmul", ArchFeature: "+avx"},
	{Op: "VDIVPS", Family: asm.FamilyVecBinOp, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "fdiv", ArchFeature: "+avx"},
	{Op: "VADDPD", Family: asm.FamilyVecBinOp, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "fadd", ArchFeature: "+avx"},
	{Op: "VSUBPD", Family: asm.FamilyVecBinOp, LaneBits: 64, Float: true, Effect: asm.EffectWriteZeroUpper, ThreeOp: true, LLVMOp: "fsub", ArchFeature: "+avx"},
	{Op: "VMULPD", Family: asm.FamilyVecBinOp, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "fmul", ArchFeature: "+avx"},
	{Op: "VDIVPD", Family: asm.FamilyVecBinOp, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "fdiv", ArchFeature: "+avx"},
	{Op: "VANDPS", Family: asm.FamilyVecBinOp, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "and", ArchFeature: "+avx"},
	{Op: "VANDPD", Family: asm.FamilyVecBinOp, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "and", ArchFeature: "+avx"},
	{Op: "VORPS", Family: asm.FamilyVecBinOp, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "or", ArchFeature: "+avx"},
	{Op: "VORPD", Family: asm.FamilyVecBinOp, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "or", ArchFeature: "+avx"},
	{Op: "VXORPS", Family: asm.FamilyVecBinOp, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "xor", ArchFeature: "+avx"},
	{Op: "VXORPD", Family: asm.FamilyVecBinOp, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "xor", ArchFeature: "+avx"},

	// Extended packed integer/FP binary ops: saturating, ANDN, PSIGN, compares, min/max, mul-high, avg
	{Op: "VPMULLQ", Family: asm.FamilyVecBinOp, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "mul", ArchFeature: "+avx512dq"},
	{Op: "ANDNPS", Family: asm.FamilyVecBinOp, LaneBits: 8, Effect: asm.EffectReadWrite, LLVMOp: "andn"},
	{Op: "VANDNPS", Family: asm.FamilyVecBinOp, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "andn", ArchFeature: "+avx"},
	{Op: "VANDNPD", Family: asm.FamilyVecBinOp, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "andn", ArchFeature: "+avx"},
	{Op: "VPANDN", Family: asm.FamilyVecBinOp, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "andn", ArchFeature: "+avx"},
	{Op: "VPANDND", Family: asm.FamilyVecBinOp, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "andn", ArchFeature: "+avx512f"},
	{Op: "VPANDNQ", Family: asm.FamilyVecBinOp, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "andn", ArchFeature: "+avx512f"},
	{Op: "PADDSB", Family: asm.FamilyVecBinOp, LaneBits: 8, Signed: true, Saturating: true, Effect: asm.EffectReadWrite, LLVMOp: "sadd.sat"},
	{Op: "PADDSW", Family: asm.FamilyVecBinOp, LaneBits: 16, Signed: true, Saturating: true, Effect: asm.EffectReadWrite, LLVMOp: "sadd.sat"},
	{Op: "PADDUSB", Family: asm.FamilyVecBinOp, LaneBits: 8, Saturating: true, Effect: asm.EffectReadWrite, LLVMOp: "uadd.sat"},
	{Op: "PADDUSW", Family: asm.FamilyVecBinOp, LaneBits: 16, Saturating: true, Effect: asm.EffectReadWrite, LLVMOp: "uadd.sat"},
	{Op: "PSUBSB", Family: asm.FamilyVecBinOp, LaneBits: 8, Signed: true, Saturating: true, Effect: asm.EffectReadWrite, LLVMOp: "ssub.sat"},
	{Op: "PSUBSW", Family: asm.FamilyVecBinOp, LaneBits: 16, Signed: true, Saturating: true, Effect: asm.EffectReadWrite, LLVMOp: "ssub.sat"},
	{Op: "PSUBUSB", Family: asm.FamilyVecBinOp, LaneBits: 8, Saturating: true, Effect: asm.EffectReadWrite, LLVMOp: "usub.sat"},
	{Op: "PSUBUSW", Family: asm.FamilyVecBinOp, LaneBits: 16, Saturating: true, Effect: asm.EffectReadWrite, LLVMOp: "usub.sat"},
	{Op: "VPADDSB", Family: asm.FamilyVecBinOp, LaneBits: 8, Signed: true, Saturating: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "sadd.sat", ArchFeature: "+avx2"},
	{Op: "VPADDSW", Family: asm.FamilyVecBinOp, LaneBits: 16, Signed: true, Saturating: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "sadd.sat", ArchFeature: "+avx2"},
	{Op: "VPADDUSB", Family: asm.FamilyVecBinOp, LaneBits: 8, Saturating: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "uadd.sat", ArchFeature: "+avx2"},
	{Op: "VPADDUSW", Family: asm.FamilyVecBinOp, LaneBits: 16, Saturating: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "uadd.sat", ArchFeature: "+avx2"},
	{Op: "VPSUBSB", Family: asm.FamilyVecBinOp, LaneBits: 8, Signed: true, Saturating: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "ssub.sat", ArchFeature: "+avx2"},
	{Op: "VPSUBSW", Family: asm.FamilyVecBinOp, LaneBits: 16, Signed: true, Saturating: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "ssub.sat", ArchFeature: "+avx2"},
	{Op: "VPSUBUSB", Family: asm.FamilyVecBinOp, LaneBits: 8, Saturating: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "usub.sat", ArchFeature: "+avx2"},
	{Op: "VPSUBUSW", Family: asm.FamilyVecBinOp, LaneBits: 16, Saturating: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "usub.sat", ArchFeature: "+avx2"},
	{Op: "MINPS", Family: asm.FamilyVecBinOp, LaneBits: 32, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "fmin"},
	{Op: "MAXPS", Family: asm.FamilyVecBinOp, LaneBits: 32, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "fmax"},
	{Op: "MINPD", Family: asm.FamilyVecBinOp, LaneBits: 64, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "fmin"},
	{Op: "MAXPD", Family: asm.FamilyVecBinOp, LaneBits: 64, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "fmax"},
	{Op: "VMINPS", Family: asm.FamilyVecBinOp, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "fmin", ArchFeature: "+avx"},
	{Op: "VMAXPS", Family: asm.FamilyVecBinOp, LaneBits: 32, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "fmax", ArchFeature: "+avx"},
	{Op: "VMINPD", Family: asm.FamilyVecBinOp, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "fmin", ArchFeature: "+avx"},
	{Op: "VMAXPD", Family: asm.FamilyVecBinOp, LaneBits: 64, Float: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "fmax", ArchFeature: "+avx"},
	{Op: "PSIGNB", Family: asm.FamilyVecBinOp, LaneBits: 8, Signed: true, Effect: asm.EffectReadWrite, LLVMOp: "psign"},
	{Op: "PSIGNW", Family: asm.FamilyVecBinOp, LaneBits: 16, Signed: true, Effect: asm.EffectReadWrite, LLVMOp: "psign"},
	{Op: "PSIGND", Family: asm.FamilyVecBinOp, LaneBits: 32, Signed: true, Effect: asm.EffectReadWrite, LLVMOp: "psign"},
	{Op: "VPSIGNB", Family: asm.FamilyVecBinOp, LaneBits: 8, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "psign", ArchFeature: "+avx2"},
	{Op: "VPSIGNW", Family: asm.FamilyVecBinOp, LaneBits: 16, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "psign", ArchFeature: "+avx2"},
	{Op: "VPSIGND", Family: asm.FamilyVecBinOp, LaneBits: 32, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "psign", ArchFeature: "+avx2"},
	{Op: "PCMPEQB", Family: asm.FamilyVecBinOp, LaneBits: 8, Effect: asm.EffectReadWrite, LLVMOp: "cmpeq"},
	{Op: "PCMPEQW", Family: asm.FamilyVecBinOp, LaneBits: 16, Effect: asm.EffectReadWrite, LLVMOp: "cmpeq"},
	{Op: "PCMPEQL", Family: asm.FamilyVecBinOp, LaneBits: 32, Effect: asm.EffectReadWrite, LLVMOp: "cmpeq"},
	{Op: "PCMPEQD", Family: asm.FamilyVecBinOp, LaneBits: 32, Effect: asm.EffectReadWrite, LLVMOp: "cmpeq"},
	{Op: "PCMPEQQ", Family: asm.FamilyVecBinOp, LaneBits: 64, Effect: asm.EffectReadWrite, LLVMOp: "cmpeq"},
	{Op: "PCMPGTB", Family: asm.FamilyVecBinOp, LaneBits: 8, Signed: true, Effect: asm.EffectReadWrite, LLVMOp: "cmpgt"},
	{Op: "PCMPGTW", Family: asm.FamilyVecBinOp, LaneBits: 16, Signed: true, Effect: asm.EffectReadWrite, LLVMOp: "cmpgt"},
	{Op: "PCMPGTL", Family: asm.FamilyVecBinOp, LaneBits: 32, Signed: true, Effect: asm.EffectReadWrite, LLVMOp: "cmpgt"},
	{Op: "PCMPGTD", Family: asm.FamilyVecBinOp, LaneBits: 32, Signed: true, Effect: asm.EffectReadWrite, LLVMOp: "cmpgt"},
	{Op: "PCMPGTQ", Family: asm.FamilyVecBinOp, LaneBits: 64, Signed: true, Effect: asm.EffectReadWrite, LLVMOp: "cmpgt"},
	{Op: "VPCMPEQB", Family: asm.FamilyVecBinOp, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cmpeq", ArchFeature: "+avx2"},
	{Op: "VPCMPEQW", Family: asm.FamilyVecBinOp, LaneBits: 16, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cmpeq", ArchFeature: "+avx2"},
	{Op: "VPCMPEQD", Family: asm.FamilyVecBinOp, LaneBits: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cmpeq", ArchFeature: "+avx2"},
	{Op: "VPCMPEQQ", Family: asm.FamilyVecBinOp, LaneBits: 64, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cmpeq", ArchFeature: "+avx2"},
	{Op: "VPCMPGTB", Family: asm.FamilyVecBinOp, LaneBits: 8, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cmpgt", ArchFeature: "+avx2"},
	{Op: "VPCMPGTW", Family: asm.FamilyVecBinOp, LaneBits: 16, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cmpgt", ArchFeature: "+avx2"},
	{Op: "VPCMPGTD", Family: asm.FamilyVecBinOp, LaneBits: 32, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cmpgt", ArchFeature: "+avx2"},
	{Op: "VPCMPGTQ", Family: asm.FamilyVecBinOp, LaneBits: 64, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cmpgt", ArchFeature: "+avx2"},
	{Op: "PAVGB", Family: asm.FamilyVecBinOp, LaneBits: 8, Effect: asm.EffectReadWrite, LLVMOp: "pavg"},
	{Op: "PAVGW", Family: asm.FamilyVecBinOp, LaneBits: 16, Effect: asm.EffectReadWrite, LLVMOp: "pavg"},
	{Op: "VPAVGB", Family: asm.FamilyVecBinOp, LaneBits: 8, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "pavg", ArchFeature: "+avx2"},
	{Op: "VPAVGW", Family: asm.FamilyVecBinOp, LaneBits: 16, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "pavg", ArchFeature: "+avx2"},
}

var x86VecOtherSpecs = []asm.OpSpec{
	{Op: "MOVOU", Family: asm.FamilyMove, Width: 128, Effect: asm.EffectWriteOnly},
	{Op: "MOVOA", Family: asm.FamilyMove, Width: 128, Effect: asm.EffectWriteOnly},
	{Op: "MOVUPS", Family: asm.FamilyMove, Width: 128, Effect: asm.EffectWriteOnly},
	{Op: "MOVAPS", Family: asm.FamilyMove, Width: 128, Effect: asm.EffectWriteOnly},
	{Op: "MOVDQU", Family: asm.FamilyMove, Width: 128, Effect: asm.EffectWriteOnly},
	{Op: "MOVDQA", Family: asm.FamilyMove, Width: 128, Effect: asm.EffectWriteOnly},
	{Op: "VMOVQ", Family: asm.FamilyMove, Effect: asm.EffectWriteZeroUpper},
	{Op: "VMOVD", Family: asm.FamilyMove, Effect: asm.EffectWriteZeroUpper},
	{Op: "VMOVDQU", Family: asm.FamilyMove, Effect: asm.EffectWriteZeroUpper},
	{Op: "VMOVDQA", Family: asm.FamilyMove, Effect: asm.EffectWriteZeroUpper},
	{Op: "VMOVAPS", Family: asm.FamilyMove, Effect: asm.EffectWriteZeroUpper},
	{Op: "VMOVAPD", Family: asm.FamilyMove, Effect: asm.EffectWriteZeroUpper},
	{Op: "VMOVDQU64", Family: asm.FamilyMove, Effect: asm.EffectWriteZeroUpper},
	{Op: "VMOVDQA64", Family: asm.FamilyMove, Effect: asm.EffectWriteZeroUpper},
	{Op: "AESENC", Family: asm.FamilyCrypto, Width: 128, Effect: asm.EffectReadWrite, ArchFeature: "+aes"},
	{Op: "AESENCLAST", Family: asm.FamilyCrypto, Width: 128, Effect: asm.EffectReadWrite, ArchFeature: "+aes"},
	{Op: "AESDEC", Family: asm.FamilyCrypto, Width: 128, Effect: asm.EffectReadWrite, ArchFeature: "+aes"},
	{Op: "AESDECLAST", Family: asm.FamilyCrypto, Width: 128, Effect: asm.EffectReadWrite, ArchFeature: "+aes"},
	{Op: "AESIMC", Family: asm.FamilyCrypto, Width: 128, Effect: asm.EffectWriteOnly, ArchFeature: "+aes"},
	{Op: "AESKEYGENASSIST", Family: asm.FamilyCrypto, Width: 128, Effect: asm.EffectWriteOnly, ArchFeature: "+aes"},
	{Op: "PCLMULQDQ", Family: asm.FamilyCrypto, Width: 128, Effect: asm.EffectReadWrite, ArchFeature: "+pclmul"},
	{Op: "VPCLMULQDQ", Family: asm.FamilyCrypto, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, ArchFeature: "+vpclmulqdq"},
	{Op: "CRC32B", Family: asm.FamilyCrypto, Width: 32, Effect: asm.EffectReadWrite, ArchFeature: "+sse4.2"},
	{Op: "CRC32W", Family: asm.FamilyCrypto, Width: 32, Effect: asm.EffectReadWrite, ArchFeature: "+sse4.2"},
	{Op: "CRC32L", Family: asm.FamilyCrypto, Width: 32, Effect: asm.EffectReadWrite, ArchFeature: "+sse4.2"},
	{Op: "CRC32Q", Family: asm.FamilyCrypto, Width: 64, Effect: asm.EffectReadWrite, ArchFeature: "+sse4.2"},
	{Op: "PREFETCHT0", Family: asm.FamilySystem, Effect: asm.EffectReadOnly},
	{Op: "PREFETCHT1", Family: asm.FamilySystem, Effect: asm.EffectReadOnly},
	{Op: "PREFETCHT2", Family: asm.FamilySystem, Effect: asm.EffectReadOnly},
	{Op: "PREFETCHNTA", Family: asm.FamilySystem, Effect: asm.EffectReadOnly},
	{Op: "PREFETCHW", Family: asm.FamilySystem, Effect: asm.EffectReadOnly},
}

// lowerDeclarativeVecBinOp lowers any FamilyVecBinOp entry from OpTable across
// 128-bit XMM, 256-bit YMM, and 512-bit ZMM registers (including EVEX K-masked
// and .Z zero-masked forms) using one parameterized LLVM IR template.
func (c *amd64Ctx) lowerDeclarativeVecBinOp(op asm.Op, ins asm.Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(ins.Op))
	zeroMask := strings.Contains(rawOp, ".Z")
	bcst := strings.Contains(rawOp, ".BCST")
	baseOp := op
	if dot := strings.IndexByte(string(baseOp), '.'); dot >= 0 {
		baseOp = asm.Op(string(baseOp)[:dot])
	}
	spec, found := OpTable.Lookup(baseOp)
	if !found || spec.Family != asm.FamilyVecBinOp || spec.LLVMOp == "" {
		return false, false, nil
	}
	args, kreg, hasMask := x86StripEVEXMask(ins.Args)
	wantArgs := 2
	if spec.ThreeOp {
		wantArgs = 3
	}
	if len(args) != wantArgs {
		return true, false, fmt.Errorf("x86 %s expects %d operands: %q", op, wantArgs, ins.Raw)
	}
	dstOp := args[wantArgs-1]
	if dstOp.Kind != asm.OpReg {
		return true, false, fmt.Errorf("x86 %s requires vector register destination: %q", op, ins.Raw)
	}

	kDst := isAMD64KReg(dstOp.Reg) && (spec.LLVMOp == "cmpeq" || spec.LLVMOp == "cmpgt")
	var vi x86VecInfo
	if kDst {
		if len(args) >= 2 && args[1].Kind == asm.OpReg {
			vi, ok = c.x86VecInfoForReg(args[1].Reg)
		}
		if !ok && args[0].Kind == asm.OpReg {
			vi, ok = c.x86VecInfoForReg(args[0].Reg)
		}
	} else {
		vi, ok = c.x86VecInfoForReg(dstOp.Reg)
	}
	if !ok {
		return true, false, fmt.Errorf("x86 %s unsupported destination register %s: %q", op, dstOp.Reg, ins.Raw)
	}
	totalBits, byteVecTy, storeVec := vi.totalBits, vi.byteVecTy, vi.storeVec

	var lhsOp, rhsOp asm.Operand
	if spec.ThreeOp {
		rhsOp, lhsOp = args[0], args[1]
	} else {
		rhsOp, lhsOp = args[0], dstOp
	}

	laneBits := int(spec.LaneBits)
	if laneBits == 0 {
		laneBits = 8
	}
	lanes := totalBits / laneBits
	elemTy := fmt.Sprintf("i%d", laneBits)
	if spec.Float {
		if laneBits == 32 {
			elemTy = "float"
		} else {
			elemTy = "double"
		}
	}
	opVecTy := fmt.Sprintf("<%d x %s>", lanes, elemTy)

	lhsRaw, err := c.x86LoadVecMasked(vi, lhsOp, false, laneBits, kreg, hasMask)
	if err != nil {
		return true, false, err
	}
	rhsRaw, err := c.x86LoadVecMasked(vi, rhsOp, bcst, laneBits, kreg, hasMask)
	if err != nil {
		return true, false, err
	}
	rhsVal := rhsRaw
	if opVecTy != byteVecTy {
		rt := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", rt, byteVecTy, rhsRaw, opVecTy)
		rhsVal = "%" + rt
	}

	lhsVal := lhsRaw
	if opVecTy != byteVecTy {
		lt := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", lt, byteVecTy, lhsRaw, opVecTy)
		lhsVal = "%" + lt
	}

	var resVal string
	switch spec.LLVMOp {
	case "umin", "umax", "smin", "smax":
		pred := map[string]string{"umin": "ult", "umax": "ugt", "smin": "slt", "smax": "sgt"}[spec.LLVMOp]
		cmp := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp %s %s %s, %s\n", cmp, pred, opVecTy, lhsVal, rhsVal)
		sel := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %s\n", sel, lanes, cmp, opVecTy, lhsVal, opVecTy, rhsVal)
		resVal = "%" + sel
	case "fmin", "fmax":
		pred := "olt"
		if spec.LLVMOp == "fmax" {
			pred = "ogt"
		}
		cmp, sel := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fcmp %s %s %s, %s\n", cmp, pred, opVecTy, lhsVal, rhsVal)
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %s\n", sel, lanes, cmp, opVecTy, lhsVal, opVecTy, rhsVal)
		resVal = "%" + sel
	case "andn":
		inv, out := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", inv, opVecTy, lhsVal, x86IntSplat(lanes, laneBits, -1))
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %s\n", out, opVecTy, inv, rhsVal)
		resVal = "%" + out
	case "sadd.sat", "uadd.sat", "ssub.sat", "usub.sat":
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.v%di%d(%s %s, %s %s)\n", out, opVecTy, spec.LLVMOp, lanes, laneBits, opVecTy, lhsVal, opVecTy, rhsVal)
		resVal = "%" + out
	case "psign":
		neg, isNeg, isZero, sel1, sel2 := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub %s zeroinitializer, %s\n", neg, opVecTy, lhsVal)
		fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, zeroinitializer\n", isNeg, opVecTy, rhsVal)
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, zeroinitializer\n", isZero, opVecTy, rhsVal)
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %%%s, %s %s\n", sel1, lanes, isNeg, opVecTy, neg, opVecTy, lhsVal)
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s zeroinitializer, %s %%%s\n", sel2, lanes, isZero, opVecTy, opVecTy, sel1)
		resVal = "%" + sel2
	case "cmpeq", "cmpgt":
		pred := "eq"
		if spec.LLVMOp == "cmpgt" {
			pred = "sgt"
		}
		cmp := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp %s %s %s, %s\n", cmp, pred, opVecTy, lhsVal, rhsVal)
		if kDst {
			bits := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i1> %%%s to i%d\n", bits, lanes, cmp, lanes)
			kv := "%" + bits
			if lanes < 64 {
				z := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = zext i%d %%%s to i64\n", z, lanes, bits)
				kv = "%" + z
			}
			if hasMask {
				km, err := c.loadK(kreg)
				if err != nil {
					return true, false, err
				}
				andK := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = and i64 %s, %s\n", andK, kv, km)
				kv = "%" + andK
			}
			return true, false, c.storeK(dstOp.Reg, kv)
		}
		sx := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sext <%d x i1> %%%s to %s\n", sx, lanes, cmp, opVecTy)
		resVal = "%" + sx
	case "pmuludq", "pmuldq":
		// Low 32 bits of each 64-bit lane multiplied to full 64-bit lane.
		l32, r32, le, re, prod := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		ty32 := fmt.Sprintf("<%d x i32>", lanes)
		ext := "zext"
		if spec.LLVMOp == "pmuldq" {
			ext = "sext"
		}
		fmt.Fprintf(c.b, "  %%%s = trunc %s %s to %s\n", l32, opVecTy, lhsVal, ty32)
		fmt.Fprintf(c.b, "  %%%s = trunc %s %s to %s\n", r32, opVecTy, rhsVal, ty32)
		fmt.Fprintf(c.b, "  %%%s = %s %s %%%s to %s\n", le, ext, ty32, l32, opVecTy)
		fmt.Fprintf(c.b, "  %%%s = %s %s %%%s to %s\n", re, ext, ty32, r32, opVecTy)
		fmt.Fprintf(c.b, "  %%%s = mul %s %%%s, %%%s\n", prod, opVecTy, le, re)
		resVal = "%" + prod
	case "pmulhw", "pmulhuw":
		wTy := fmt.Sprintf("<%d x i32>", lanes)
		ext := "zext"
		if spec.LLVMOp == "pmulhw" {
			ext = "sext"
		}
		lw, rw, prod, sh, tr := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", lw, ext, opVecTy, lhsVal, wTy)
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", rw, ext, opVecTy, rhsVal, wTy)
		fmt.Fprintf(c.b, "  %%%s = mul %s %%%s, %%%s\n", prod, wTy, lw, rw)
		fmt.Fprintf(c.b, "  %%%s = lshr %s %%%s, %s\n", sh, wTy, prod, x86IntSplat(lanes, 32, 16))
		fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", tr, wTy, sh, opVecTy)
		resVal = "%" + tr
	case "pavg":
		wBits := laneBits * 2
		wTy := fmt.Sprintf("<%d x i%d>", lanes, wBits)
		lz, rz, sum, sum1, sh, tr := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", lz, opVecTy, lhsVal, wTy)
		fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", rz, opVecTy, rhsVal, wTy)
		fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", sum, wTy, lz, rz)
		fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %s\n", sum1, wTy, sum, x86IntSplat(lanes, wBits, 1))
		fmt.Fprintf(c.b, "  %%%s = lshr %s %%%s, %s\n", sh, wTy, sum1, x86IntSplat(lanes, wBits, 1))
		fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", tr, wTy, sh, opVecTy)
		resVal = "%" + tr
	default:
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", out, spec.LLVMOp, opVecTy, lhsVal, rhsVal)
		resVal = "%" + out
	}

	if hasMask {
		oldRaw, err := vi.loadReg(dstOp.Reg)
		if err != nil {
			return true, false, err
		}
		oldVal := oldRaw
		if opVecTy != byteVecTy {
			obc := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", obc, byteVecTy, oldRaw, opVecTy)
			oldVal = "%" + obc
		}
		resVal, err = c.x86ApplyMask(kreg, zeroMask, lanes, opVecTy, resVal, oldVal)
		if err != nil {
			return true, false, err
		}
	}

	if opVecTy != byteVecTy {
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bc, opVecTy, resVal, byteVecTy)
		resVal = "%" + bc
	}
	if err := storeVec(dstOp.Reg, resVal); err != nil {
		return true, false, err
	}
	return true, false, nil
}

func isAMD64XReg(r asm.Reg) bool { _, ok := amd64ParseXReg(r); return ok }
func isAMD64YReg(r asm.Reg) bool { _, ok := amd64ParseYReg(r); return ok }

// DeclarativeOpNames returns all opcodes registered in x86 OpTable.
func DeclarativeOpNames() []string {
	ops := OpTable.SupportedOps()
	out := make([]string, len(ops))
	for i, op := range ops {
		out[i] = strings.ToUpper(string(op))
	}
	return out
}
