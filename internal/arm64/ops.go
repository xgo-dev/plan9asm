package arm64

import (
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// OpTable is the declarative AArch64 instruction specification table, mirroring
// Go's cmd/internal/obj/arm64 optab for LLVM IR lowering and ABI0 analysis.
var OpTable = asm.NewOpTable(
	arm64ScalarSpecs,
	arm64BranchAtomicSpecs,
	arm64SIMDAndCryptoSpecs,
	arm64ExtraScalarSpecs,
	arm64DeclarativeFPSpecs,
	arm64NEONSpecs,
	arm64SVESpecs,
)

var arm64ScalarSpecs = []asm.OpSpec{
	{Op: "MOVD", Family: asm.FamilyMove, Width: 64, Effect: asm.EffectWriteOnly},
	{Op: "MOVW", Family: asm.FamilyMove, Width: 32, Effect: asm.EffectWriteZeroUpper},
	{Op: "MOVWU", Family: asm.FamilyMove, Width: 32, Effect: asm.EffectWriteZeroUpper},
	{Op: "MOVH", Family: asm.FamilyMove, Width: 16, Signed: true, Effect: asm.EffectWriteOnly},
	{Op: "MOVHU", Family: asm.FamilyMove, Width: 16, Effect: asm.EffectWriteZeroUpper},
	{Op: "MOVB", Family: asm.FamilyMove, Width: 8, Signed: true, Effect: asm.EffectWriteOnly},
	{Op: "MOVBU", Family: asm.FamilyMove, Width: 8, Effect: asm.EffectWriteZeroUpper},
	{Op: "LDP", Family: asm.FamilyMove, Width: 128, Effect: asm.EffectWriteOnly},
	{Op: "STP", Family: asm.FamilyMove, Width: 128, Effect: asm.EffectReadOnly},

	{Op: "ADD", Family: asm.FamilyALU, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "add"},
	{Op: "ADDW", Family: asm.FamilyALU, Width: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "add"},
	{Op: "ADDS", Family: asm.FamilyALU, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, Flags: asm.FlagsWrite, LLVMOp: "add"},
	{Op: "ADDSW", Family: asm.FamilyALU, Width: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, Flags: asm.FlagsWrite, LLVMOp: "add"},
	{Op: "SUB", Family: asm.FamilyALU, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "sub"},
	{Op: "SUBW", Family: asm.FamilyALU, Width: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "sub"},
	{Op: "SUBS", Family: asm.FamilyALU, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, Flags: asm.FlagsWrite, LLVMOp: "sub"},
	{Op: "SUBSW", Family: asm.FamilyALU, Width: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, Flags: asm.FlagsWrite, LLVMOp: "sub"},
	{Op: "AND", Family: asm.FamilyALU, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "and"},
	{Op: "ANDW", Family: asm.FamilyALU, Width: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "and"},
	{Op: "ANDS", Family: asm.FamilyALU, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, Flags: asm.FlagsWrite, LLVMOp: "and"},
	{Op: "ORR", Family: asm.FamilyALU, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "or"},
	{Op: "ORRW", Family: asm.FamilyALU, Width: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "or"},
	{Op: "EOR", Family: asm.FamilyALU, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "xor"},
	{Op: "EORW", Family: asm.FamilyALU, Width: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "xor"},
	{Op: "CMP", Family: asm.FamilyCompare, Width: 64, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite},
	{Op: "CMPW", Family: asm.FamilyCompare, Width: 32, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite},
	{Op: "TST", Family: asm.FamilyCompare, Width: 64, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite},
	{Op: "TSTW", Family: asm.FamilyCompare, Width: 32, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite},
	{Op: "LSL", Family: asm.FamilyShift, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "shl"},
	{Op: "LSR", Family: asm.FamilyShift, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "lshr"},
	{Op: "ASR", Family: asm.FamilyShift, Width: 64, Signed: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "ashr"},
	{Op: "MUL", Family: asm.FamilyMulDiv, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "mul"},
	{Op: "UMULH", Family: asm.FamilyMulDiv, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly},
	{Op: "SMULH", Family: asm.FamilyMulDiv, Width: 64, Signed: true, ThreeOp: true, Effect: asm.EffectWriteOnly},
	{Op: "CSEL", Family: asm.FamilyCMov, Width: 64, Effect: asm.EffectWriteOnly, Flags: asm.FlagsRead},
	{Op: "CSET", Family: asm.FamilyCMov, Width: 64, Effect: asm.EffectWriteOnly, Flags: asm.FlagsRead},
	{Op: "CLZ", Family: asm.FamilyBit, Width: 64, Effect: asm.EffectWriteOnly},
	{Op: "RBIT", Family: asm.FamilyBit, Width: 64, Effect: asm.EffectWriteOnly},
	{Op: "REV", Family: asm.FamilyBit, Width: 64, Effect: asm.EffectWriteOnly},
}

var arm64BranchAtomicSpecs = []asm.OpSpec{
	{Op: "B", Family: asm.FamilyBranch, Effect: asm.EffectReadOnly},
	{Op: "BL", Family: asm.FamilyBranch, Effect: asm.EffectImplicit, Flags: asm.FlagsClobber},
	{Op: "CBZ", Family: asm.FamilyBranch, Effect: asm.EffectReadOnly},
	{Op: "CBNZ", Family: asm.FamilyBranch, Effect: asm.EffectReadOnly},
	{Op: "TBZ", Family: asm.FamilyBranch, Effect: asm.EffectReadOnly},
	{Op: "TBNZ", Family: asm.FamilyBranch, Effect: asm.EffectReadOnly},
	{Op: "RET", Family: asm.FamilyBranch, Effect: asm.EffectReadOnly},
	{Op: "SVC", Family: asm.FamilySyscall, Effect: asm.EffectImplicit, Flags: asm.FlagsWrite},
	{Op: "SB", Family: asm.FamilySystem, Effect: asm.EffectNone},
	{Op: "MRS", Family: asm.FamilySystem, Width: 64, Effect: asm.EffectWriteOnly},
	{Op: "LDAR", Family: asm.FamilyAtomic, Width: 64, Effect: asm.EffectWriteOnly},
	{Op: "STLR", Family: asm.FamilyAtomic, Width: 64, Effect: asm.EffectReadOnly},
	{Op: "CASALD", Family: asm.FamilyAtomic, Width: 64, Effect: asm.EffectReadWrite, ArchFeature: "+lse"},
	{Op: "LDADDALD", Family: asm.FamilyAtomic, Width: 64, Effect: asm.EffectWriteOnly, ArchFeature: "+lse"},
	{Op: "SWPALD", Family: asm.FamilyAtomic, Width: 64, Effect: asm.EffectWriteOnly, ArchFeature: "+lse"},
}

var arm64SIMDAndCryptoSpecs = []asm.OpSpec{
	{Op: "VADD", Family: asm.FamilyVecBinOp, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "add"},
	{Op: "VSUB", Family: asm.FamilyVecBinOp, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "sub"},
	{Op: "VEOR", Family: asm.FamilyVecBinOp, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "xor"},
	{Op: "VAND", Family: asm.FamilyVecBinOp, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "and"},
	{Op: "VORR", Family: asm.FamilyVecBinOp, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "or"},
	{Op: "AESE", Family: asm.FamilyCrypto, Width: 128, Effect: asm.EffectReadWrite, ArchFeature: "+aes"},
	{Op: "AESD", Family: asm.FamilyCrypto, Width: 128, Effect: asm.EffectReadWrite, ArchFeature: "+aes"},
	{Op: "AESMC", Family: asm.FamilyCrypto, Width: 128, Effect: asm.EffectWriteOnly, ArchFeature: "+aes"},
	{Op: "AESIMC", Family: asm.FamilyCrypto, Width: 128, Effect: asm.EffectWriteOnly, ArchFeature: "+aes"},
	{Op: "CRC32B", Family: asm.FamilyCrypto, Width: 32, Effect: asm.EffectReadWrite, ArchFeature: "+crc"},
	{Op: "CRC32H", Family: asm.FamilyCrypto, Width: 32, Effect: asm.EffectReadWrite, ArchFeature: "+crc"},
	{Op: "CRC32W", Family: asm.FamilyCrypto, Width: 32, Effect: asm.EffectReadWrite, ArchFeature: "+crc"},
	{Op: "CRC32X", Family: asm.FamilyCrypto, Width: 64, Effect: asm.EffectReadWrite, ArchFeature: "+crc"},
	{Op: "CRC32CB", Family: asm.FamilyCrypto, Width: 32, Effect: asm.EffectReadWrite, ArchFeature: "+crc"},
	{Op: "CRC32CH", Family: asm.FamilyCrypto, Width: 32, Effect: asm.EffectReadWrite, ArchFeature: "+crc"},
	{Op: "CRC32CW", Family: asm.FamilyCrypto, Width: 32, Effect: asm.EffectReadWrite, ArchFeature: "+crc"},
	{Op: "CRC32CX", Family: asm.FamilyCrypto, Width: 64, Effect: asm.EffectReadWrite, ArchFeature: "+crc"},
}

// DeclarativeOpNames returns all opcodes registered in arm64 OpTable.
func DeclarativeOpNames() []string {
	ops := OpTable.SupportedOps()
	out := make([]string, len(ops))
	for i, op := range ops {
		out[i] = strings.ToUpper(string(op))
	}
	return out
}
