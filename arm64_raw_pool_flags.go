package plan9asm

import (
	"encoding/binary"

	"golang.org/x/arch/arm64/arm64asm"
)

func (expression arm64PoolAffine) registerMask() uint32 {
	var mask uint32
	for index, coefficient := range expression.coefficient {
		if coefficient != 0 {
			mask |= 1 << uint(index)
		}
	}
	return mask
}

// Follow a single dominating predecessor chain to the flags' definition.
// Every intervening instruction must preserve NZCV, and the caller must also
// check that it did not overwrite a register used in the comparison. Merely
// finding an earlier CMP in the instruction stream proves neither property.
func (flow *arm64RawPoolValues) affineFlagsBefore(at int) (uint32, uint32, bool) {
	word, clobbered, _, ok := flow.affineFlagSourceBefore(at)
	return word, clobbered, ok
}

// after is the point just after the defining arithmetic instruction. A guard
// whose GP operands were overwritten later can still constrain their historic
// values here, never their unrelated replacements at the branch.
func (flow *arm64RawPoolValues) affineFlagSourceBefore(at int) (uint32, uint32, int, bool) {
	var clobbered uint32
	for steps := 0; steps < 512; steps++ {
		if at < 0 || at >= len(flow.before) || len(flow.before[at]) != 1 {
			return 0, 0, 0, false
		}
		at = flow.before[at][0]
		if at < 0 {
			return 0, 0, 0, false
		}
		word := flow.words[at]
		if arm64RawPoolSVEPreservesNZCV(word) {
			// x/arch does not decode these SVE families. Reuse their typed
			// grammar, but keep flag effects separate from GP write effects.
			writes, known := arm64RawPoolGPWrites(word)
			if !known {
				return 0, 0, 0, false
			}
			clobbered |= writes
			continue
		}
		var code [4]byte
		binary.LittleEndian.PutUint32(code[:], word)
		ins, err := arm64asm.Decode(code[:])
		if err != nil {
			return 0, 0, 0, false
		}
		switch ins.Op {
		case arm64asm.CMP, arm64asm.CMN, arm64asm.ADDS, arm64asm.SUBS:
			if word>>31 == 0 {
				return 0, 0, 0, false // A W comparison does not constrain an X value.
			}
			return word, clobbered, at + 1, true
		}
		writes, known := arm64RawPoolGPWrites(word)
		if !known || !arm64RawPoolPreservesNZCV(ins.Op) {
			return 0, 0, 0, false
		}
		clobbered |= writes
	}
	return 0, 0, 0, false
}

// These complete vector families preserve NZCV. Predicate logical operations
// instead share the lowerer's explicit flag bit; their S variants cannot carry
// an earlier scalar comparison. In particular, no-GP-output is insufficient:
// SVE comparisons, WHILE*, PTEST and unknown instructions remain barriers.
func arm64RawPoolSVEPreservesNZCV(word uint32) bool {
	if _, ok := decodeARM64RawSVEEOR(word); ok {
		return true
	}
	if _, ok := decodeARM64RawSVEUnpack(word); ok {
		return true
	}
	if _, ok := decodeARM64RawSVEMultiplyAccumulate(word); ok {
		return true
	}
	if _, ok := decodeARM64RawSVEIntegerReduction(word); ok {
		return true
	}
	if _, ok := decodeARM64RawSVEIntegerAddReduction(word); ok {
		return true
	}
	if ins, ok := decodeARM64RawSVEPredicateLogical(word); ok {
		spec, known := arm64SVEPredicateLogicalSpecs[ins.Op]
		return known && !spec.flags
	}
	return false
}

// An explicit effect whitelist, not a guess from a mnemonic suffix. In
// particular floating comparisons, system operations and unknown SVE flag
// effects must stop the proof even when they have no general-register output.
func arm64RawPoolPreservesNZCV(op arm64asm.Op) bool {
	if arm64RawPoolReadOnlyLoad(op) {
		return true
	}
	switch op {
	case arm64asm.NOP, arm64asm.ADR, arm64asm.MOV, arm64asm.MOVK, arm64asm.MOVN, arm64asm.MOVZ,
		arm64asm.ADD, arm64asm.SUB, arm64asm.ADC, arm64asm.SBC, arm64asm.NEG, arm64asm.NGC,
		arm64asm.AND, arm64asm.BIC, arm64asm.ORR, arm64asm.ORN, arm64asm.EOR, arm64asm.EON, arm64asm.MVN,
		arm64asm.LSL, arm64asm.LSR, arm64asm.ASR, arm64asm.ROR,
		arm64asm.FMOV, arm64asm.UMOV, arm64asm.SMOV, arm64asm.ADDP, arm64asm.FADDP,
		arm64asm.MUL, arm64asm.MNEG, arm64asm.MADD, arm64asm.MSUB,
		arm64asm.SMADDL, arm64asm.SMSUBL, arm64asm.SMULL, arm64asm.SMNEGL, arm64asm.SMULH,
		arm64asm.UMADDL, arm64asm.UMSUBL, arm64asm.UMULL, arm64asm.UMNEGL, arm64asm.UMULH,
		arm64asm.EXT, arm64asm.UXTL, arm64asm.UXTL2, arm64asm.SXTL, arm64asm.SXTL2,
		arm64asm.CMEQ, arm64asm.CMGE, arm64asm.CMGT, arm64asm.CMHI, arm64asm.CMHS,
		arm64asm.CMLE, arm64asm.CMLT, arm64asm.CMTST,
		arm64asm.CSEL, arm64asm.CSINC, arm64asm.CSINV, arm64asm.CSNEG,
		arm64asm.CSET, arm64asm.CSETM, arm64asm.CINC, arm64asm.CINV, arm64asm.CNEG,
		arm64asm.STR, arm64asm.STRB, arm64asm.STRH, arm64asm.STUR, arm64asm.STURB, arm64asm.STURH,
		arm64asm.STTR, arm64asm.STTRB, arm64asm.STTRH, arm64asm.STLR, arm64asm.STLRB, arm64asm.STLRH,
		arm64asm.STP, arm64asm.STNP, arm64asm.ST1, arm64asm.ST2, arm64asm.ST3, arm64asm.ST4:
		return true
	}
	return false
}
