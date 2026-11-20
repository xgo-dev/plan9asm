package plan9asm

import (
	"strings"

	"golang.org/x/arch/arm64/arm64asm"
)

// This is a separate SDK opaque-body admission contract. An explicit ABI0
// wrapper supplies only its actual integer/pointer tuple. It does not supply
// closure, g, platform registers, native SP addresses, NZCV or FP/SIMD inputs.
// The body may define ordinary registers itself, but no resulting value is
// transferred to the translator or the caller by this observation.
func arm64ScratchSDKTuple(function Func, signature FuncSig) (uint64, bool) {
	if function.FrameSize != 0 || len(function.Instrs) == 0 ||
		signature.Ret != Void || len(signature.Args) == 0 || len(signature.Args) > 8 ||
		len(signature.Frame.Results) != 0 || len(signature.Frame.Params) != len(signature.Args) ||
		len(signature.ArgRegs) != 0 || signature.ARM64GoRegisterABI != nil || signature.ARM64ClosureABI != nil {
		return 0, false
	}
	_, text := splitOpcode(function.Instrs[0].Raw)
	parts := strings.Split(text, ",")
	if len(parts) != 3 || !strings.Contains(parts[2], "-") || function.ArgSize != int64(len(signature.Args))*8 {
		return 0, false
	}
	for index, argument := range signature.Args {
		slot := signature.Frame.Params[index]
		if argument != I64 && argument != Ptr || slot.Type != argument || slot.Index != index || slot.Offset != int64(index)*8 {
			return 0, false
		}
	}
	return uint64(1)<<uint(len(signature.Args)) - 1, true
}

// NZCV uses its architectural nibble ordering. Conditional selection and
// branches read only their actual condition bits; CBZ/CBNZ and TBZ/TBNZ read
// GP operands rather than NZCV. No unknown flag writer can preserve a fact.
func arm64ScratchConditionInputs(condition arm64asm.Cond) (uint64, bool) {
	var bits uint64
	switch condition.String() {
	case "EQ", "NE":
		bits = 4
	case "CS", "CC":
		bits = 2
	case "MI", "PL":
		bits = 8
	case "VS", "VC":
		bits = 1
	case "HI", "LS":
		bits = 6
	case "GE", "LT":
		bits = 9
	case "GT", "LE":
		bits = 13
	case "AL":
	default:
		return 0, false
	}
	return bits << 31, true
}

func arm64ScratchSDKArgumentInputs(argument arm64asm.Arg) (uint64, bool) {
	switch argument := argument.(type) {
	case nil, arm64asm.Imm, arm64asm.Imm64, arm64asm.ImmShift, arm64asm.PCRel:
		return 0, true
	case arm64asm.Cond:
		return arm64ScratchConditionInputs(argument)
	case arm64asm.Reg:
		if argument == arm64asm.WZR || argument == arm64asm.XZR {
			return 0, true
		}
		index, valid := arm64RawPoolGP(argument)
		return uint64(1) << uint(index), valid && index != 30
	case arm64asm.RegSP:
		if arm64asm.Reg(argument) == arm64asm.SP || arm64asm.Reg(argument) == arm64asm.WSP {
			return 0, false
		}
		return arm64ScratchSDKArgumentInputs(arm64asm.Reg(argument))
	case arm64asm.RegExtshiftAmount:
		// The typed decoder validates the shift/extension. Its private register
		// is printed first; only exact GP names are accepted, not F/V aliases.
		name, _, _ := strings.Cut(argument.String(), ",")
		for index := 0; index < 30; index++ {
			if name == arm64asm.Reg(int(arm64asm.X0)+index).String() ||
				name == arm64asm.Reg(int(arm64asm.W0)+index).String() {
				return uint64(1) << uint(index), true
			}
		}
		return 0, false
	case arm64asm.MemImmediate:
		if argument.Mode == arm64asm.AddrPostReg {
			return 0, false
		}
		return arm64ScratchSDKArgumentInputs(argument.Base)
	case arm64asm.MemExtend:
		base, baseValid := arm64ScratchSDKArgumentInputs(argument.Base)
		index, indexValid := arm64ScratchSDKArgumentInputs(argument.Index)
		return base | index, baseValid && indexValid
	default:
		return 0, false
	}
}

func arm64ScratchSDKNativeEffect(instruction arm64asm.Inst) (arm64ScratchInputEffect, bool) {
	return arm64ScratchNativeInputEffect(instruction, false)
}

func arm64ScratchNativeInputEffect(instruction arm64asm.Inst, sourceStack bool) (arm64ScratchInputEffect, bool) {
	if form, valid := decodeARM64RawNZCV(instruction.Enc); valid {
		reads, writes := form.gpEffects()
		if (reads|writes)&(1<<30) != 0 || writes&((1<<18)|(1<<28)) != 0 {
			return arm64ScratchInputEffect{}, false // No LR or platform/g output contract.
		}
		effect := arm64ScratchInputEffect{reads: uint64(reads), writes: uint64(writes)}
		if !form.read {
			effect.writes |= 15 << 31
		} else if form.reg != ZR {
			effect.reads |= 15 << 31
		}
		return effect, true
	}
	if form, valid := decodeARM64RawScalarRegister(instruction.Enc); valid {
		reads, writes, stack := form.gpEffects()
		if stack || (reads|writes)&(1<<30) != 0 {
			return arm64ScratchInputEffect{}, false // No numerical SP/LR contract.
		}
		effect := arm64ScratchInputEffect{reads: uint64(reads), writes: uint64(writes)}
		if form.flags {
			effect.writes |= 15 << 31
		}
		return effect, true
	}
	if form, valid := decodeARM64RawBitfield(instruction.Enc); valid {
		reads, writes := form.gpEffects()
		if (reads|writes)&(1<<30) != 0 {
			return arm64ScratchInputEffect{}, false // No native LR data contract.
		}
		return arm64ScratchInputEffect{reads: uint64(reads), writes: uint64(writes)}, true
	}
	if instruction.Op == arm64asm.RET {
		return arm64ScratchInputEffect{}, instruction.Enc == 0xd65f03c0
	}
	// A native SDK call needs a separate same-call register/tuple transfer
	// proof. The R27 transitive summary alone does not supply such an entry.
	if instruction.Op == arm64asm.BL {
		return arm64ScratchInputEffect{}, false
	}
	if _, valid := arm64ScratchNativeEffect(instruction); !valid {
		return arm64ScratchInputEffect{}, false
	}
	writes, known := arm64RawPoolGPWrites(instruction.Enc)
	if !known {
		return arm64ScratchInputEffect{}, false
	}
	effect := arm64ScratchInputEffect{writes: uint64(writes)}
	destinations := 0
	word := instruction.Enc
	switch {
	case word&0x1c000000 == 0x10000000, word&0x0e000000 == 0x0a000000, word&0x0e000000 == 0x0e000000:
		destinations = 1
		switch instruction.Op {
		case arm64asm.CMP, arm64asm.CMN, arm64asm.TST, arm64asm.CCMP, arm64asm.CCMN:
			destinations = 0
		}
	case arm64RawPoolReadOnlyLoad(instruction.Op):
		destinations = 1
		if instruction.Op == arm64asm.LDP || instruction.Op == arm64asm.LDNP || instruction.Op == arm64asm.LDPSW {
			destinations = 2
		}
	}
	for index, argument := range instruction.Args {
		reads, valid := arm64ScratchSDKArgumentInputs(argument)
		if sourceStack {
			if memory, stack := argument.(arm64asm.MemImmediate); stack && arm64asm.Reg(memory.Base) == arm64asm.SP {
				// Exact source-local load/store roles were independently checked.
				// SP is never supplied as a numerical GP fact. Generated frame
				// operations are matched separately before reaching this path.
				reads, valid = 0, memory.Mode == arm64asm.AddrOffset
			}
		}
		if !valid {
			return arm64ScratchInputEffect{}, false
		}
		if index < destinations {
			if _, direct := argument.(arm64asm.Reg); direct {
				reads = 0
			}
			if _, direct := argument.(arm64asm.RegSP); direct {
				reads = 0
			}
		}
		effect.reads |= reads
	}
	switch instruction.Op {
	case arm64asm.MOVK, arm64asm.BFM, arm64asm.BFI, arm64asm.BFXIL:
		effect.reads |= uint64(writes)
	}
	switch instruction.Op {
	case arm64asm.ADC, arm64asm.SBC, arm64asm.NGC:
		effect.reads |= 2 << 31
	case arm64asm.ADCS, arm64asm.SBCS, arm64asm.NGCS:
		effect.reads |= 2 << 31
		effect.writes |= 15 << 31
	case arm64asm.CMP, arm64asm.CMN, arm64asm.TST, arm64asm.ADDS, arm64asm.SUBS,
		arm64asm.ANDS, arm64asm.BICS, arm64asm.NEGS, arm64asm.CCMP, arm64asm.CCMN:
		effect.writes |= 15 << 31
	case arm64asm.B, arm64asm.CBZ, arm64asm.CBNZ, arm64asm.TBZ, arm64asm.TBNZ, arm64asm.ADRP:
	default:
		if !arm64RawPoolInstructionPreservesNZCV(instruction) {
			return arm64ScratchInputEffect{}, false
		}
	}
	return effect, true
}

func arm64ScratchSDKBodyInputs(body arm64ScratchNativeBody, seed uint64) bool {
	instructions, edges, valid := arm64ScratchNativeGraph(body)
	if !valid {
		return false
	}
	effects := make([]arm64ScratchInputEffect, len(instructions))
	for index, instruction := range instructions {
		effect, valid := arm64ScratchSDKNativeEffect(instruction)
		if !valid {
			return false
		}
		effects[index] = effect
	}
	return arm64ScratchNativeAvailable(effects, edges, seed)
}
