package plan9asm

import (
	"encoding/binary"
	"strings"

	"golang.org/x/arch/arm64/arm64asm"
)

// These facts concern only dependence on incoming physical R27. They neither
// carry a pointer value nor describe an initialized/native memory region.
type arm64ScratchEffect struct {
	reads, defines, call bool
}

func arm64ScratchArgumentReads(argument arm64asm.Arg) (bool, bool) {
	switch argument := argument.(type) {
	case nil, arm64asm.Imm, arm64asm.Imm64, arm64asm.ImmShift, arm64asm.Cond, arm64asm.PCRel:
		return false, true
	case arm64asm.Reg:
		return argument == arm64asm.X27 || argument == arm64asm.W27, true
	case arm64asm.RegSP:
		return arm64asm.Reg(argument) == arm64asm.X27 || arm64asm.Reg(argument) == arm64asm.W27, true
	case arm64asm.RegExtshiftAmount:
		// x/arch keeps the register private; its validated typed printer's
		// first field is exactly one register, not an arbitrary instruction.
		name, _, _ := strings.Cut(argument.String(), ",")
		return name == "X27" || name == "W27", true
	case arm64asm.MemImmediate:
		if argument.Mode == arm64asm.AddrPostReg {
			return false, false // The private post-register field has no shared effect row here.
		}
		return arm64asm.Reg(argument.Base) == arm64asm.X27, true
	case arm64asm.MemExtend:
		return arm64asm.Reg(argument.Base) == arm64asm.X27 || argument.Index == arm64asm.X27 || argument.Index == arm64asm.W27, true
	default:
		return false, false
	}
}

func arm64ScratchNativeEffect(instruction arm64asm.Inst) (arm64ScratchEffect, bool) {
	const scratch = uint32(1 << 27)
	word := instruction.Enc
	if form, valid := decodeARM64RawNZCV(word); valid {
		reads, writes := form.gpEffects()
		return arm64ScratchEffect{reads: reads&scratch != 0, defines: writes&scratch != 0}, true
	}
	if form, valid := decodeARM64RawScalarRegister(word); valid {
		reads, writes, _ := form.gpEffects()
		return arm64ScratchEffect{reads: reads&scratch != 0, defines: writes&scratch != 0}, true
	}
	if form, valid := decodeARM64RawBitfield(word); valid {
		reads, writes := form.gpEffects()
		return arm64ScratchEffect{reads: reads&scratch != 0, defines: writes&scratch != 0}, true
	}
	switch instruction.Op {
	case arm64asm.RET:
		return arm64ScratchEffect{}, word == 0xd65f03c0
	case arm64asm.BL:
		return arm64ScratchEffect{call: true}, word == 0x94000000
	case arm64asm.B, arm64asm.CBZ, arm64asm.CBNZ, arm64asm.TBZ, arm64asm.TBNZ:
		var effect arm64ScratchEffect
		for _, argument := range instruction.Args {
			reads, valid := arm64ScratchArgumentReads(argument)
			if !valid {
				return arm64ScratchEffect{}, false
			}
			effect.reads = effect.reads || reads
		}
		return effect, true
	case arm64asm.BR, arm64asm.BLR, arm64asm.SVC, arm64asm.HVC, arm64asm.SMC,
		arm64asm.ERET, arm64asm.MSR, arm64asm.MRS:
		return arm64ScratchEffect{}, false
	}
	// The registered raw families already bind their complete operand/bank
	// effects. This observation adds no permission to lower any such opcode.
	if effect, known := arm64RawContinuationEffectsForWord(word); known {
		return arm64ScratchEffect{reads: effect.gpReads&scratch != 0, defines: effect.gpWrites&scratch != 0}, true
	}
	writes, known := arm64RawPoolGPWrites(word)
	if !known {
		return arm64ScratchEffect{}, false
	}
	destinations := 0
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
	effect := arm64ScratchEffect{defines: writes&scratch != 0}
	for index, argument := range instruction.Args {
		reads, valid := arm64ScratchArgumentReads(argument)
		if !valid {
			return arm64ScratchEffect{}, false
		}
		if index < destinations {
			if _, direct := argument.(arm64asm.Reg); direct {
				reads = false
			}
			if _, direct := argument.(arm64asm.RegSP); direct {
				reads = false
			}
		}
		effect.reads = effect.reads || reads
	}
	// Wide immediate insertion and bitfield insertion are read-modify-write,
	// including W forms. A W overwrite otherwise defines the whole X alias
	// through architectural zero extension, not a declaration/padding guess.
	switch instruction.Op {
	case arm64asm.MOVK, arm64asm.BFM, arm64asm.BFI, arm64asm.BFXIL:
		effect.reads = effect.reads || effect.defines
	}
	return effect, true
}

func arm64ScratchNativeRelocations(body arm64ScratchNativeBody) bool {
	occupied := make(map[int]bool)
	calls := 0
	for _, relocation := range body.relocs {
		at := relocation.at
		if at < 0 || at >= len(body.code) || relocation.target == "" || occupied[at] {
			return false
		}
		occupied[at] = true
		if relocation.kind == "R_CALLARM64" {
			if relocation.width != 4 || relocation.addend != 0 || body.code[at] != 0x94000000 ||
				calls >= len(body.calls) || body.calls[calls] != relocation.target {
				return false
			}
			calls++
			continue
		}
		if relocation.width != 8 || at+1 >= len(body.code) || occupied[at+1] || body.code[at]&0x9f000000 != 0x90000000 {
			return false
		}
		occupied[at+1] = true
		first, second := body.code[at], body.code[at+1]
		if relocation.kind == "R_ADDRARM64" {
			if second&0xffc00000 != 0x91000000 || first&31 != second>>5&31 || first&31 != second&31 {
				return false
			}
			continue
		}
		sizes := map[string]uint32{"R_ARM64_PCREL_LDST8": 0, "R_ARM64_PCREL_LDST16": 1,
			"R_ARM64_PCREL_LDST32": 2, "R_ARM64_PCREL_LDST64": 3}
		size, known := sizes[relocation.kind]
		if !known || second&0x3f000000 != 0x39000000 || second>>30 != size || first&31 != second>>5&31 {
			return false
		}
	}
	return calls == len(body.calls)
}

// All native observations share the actual instruction/relocation CFG. This
// constructs edges only; it cannot supply a register, address or entry fact.
func arm64ScratchNativeGraph(body arm64ScratchNativeBody) ([]arm64asm.Inst, [][]int, bool) {
	code := body.code
	for len(code) != 0 && code[len(code)-1] == 0 {
		code = code[:len(code)-1]
	}
	if len(code) == 0 || len(code) > 65536 || !arm64ScratchNativeRelocations(body) {
		return nil, nil, false
	}
	instructions := make([]arm64asm.Inst, len(code))
	edges := make([][]int, len(code))
	returned, calls := false, 0
	for ordinal, word := range code {
		var bytes [4]byte
		binary.LittleEndian.PutUint32(bytes[:], word)
		instruction, err := arm64asm.Decode(bytes[:])
		effect, valid := arm64ScratchNativeEffect(instruction)
		if err != nil || !valid {
			return nil, nil, false
		}
		instructions[ordinal] = instruction
		if effect.call {
			calls++
		}
		if instruction.Op == arm64asm.RET {
			returned = true
			continue
		}
		branch := instruction.Op == arm64asm.B || instruction.Op == arm64asm.CBZ || instruction.Op == arm64asm.CBNZ ||
			instruction.Op == arm64asm.TBZ || instruction.Op == arm64asm.TBNZ
		if branch {
			targets := 0
			for _, argument := range instruction.Args {
				if relative, ok := argument.(arm64asm.PCRel); ok {
					destination := int64(ordinal)*4 + int64(relative)
					if destination < 0 || destination%4 != 0 || destination/4 >= int64(len(code)) {
						return nil, nil, false
					}
					edges[ordinal] = append(edges[ordinal], int(destination/4))
					targets++
				}
			}
			if targets != 1 {
				return nil, nil, false
			}
		}
		if word&0xfc000000 != 0x14000000 {
			if ordinal+1 == len(code) {
				return nil, nil, false // Actual native fallthrough is not an implicit RET.
			}
			edges[ordinal] = append(edges[ordinal], ordinal+1)
		}
	}
	if !returned || calls != len(body.calls) {
		return nil, nil, false
	}
	return instructions, edges, true
}

type arm64ScratchInputEffect struct {
	reads, writes uint64
	call          bool
}

// Inputs are intersected at every join. The first native entry receives only
// its independently proved seed; disconnected components start fully unknown.
// There are at most 35 changing GP/NZCV facts and two successors per word.
func arm64ScratchNativeAvailable(effects []arm64ScratchInputEffect, edges [][]int, seed uint64) bool {
	seen, defined := make([]bool, len(effects)), make([]uint64, len(effects))
	steps := 0
	for entry := range effects {
		if seen[entry] {
			continue
		}
		seen[entry] = true
		if entry == 0 {
			defined[entry] = seed
		}
		queue := []int{entry}
		for len(queue) != 0 {
			at := queue[0]
			queue = queue[1:]
			steps++
			if steps > len(effects)*72 {
				return false
			}
			if effects[at].reads & ^defined[at] != 0 {
				return false
			}
			out := defined[at] | effects[at].writes
			if effects[at].call {
				out = 0
			}
			for _, next := range edges[at] {
				value := out
				if seen[next] {
					value = defined[next] & out
				}
				if !seen[next] || value != defined[next] {
					seen[next], defined[next] = true, value
					queue = append(queue, next)
				}
			}
		}
	}
	return true
}

// A must-defined CFG proves that no component, including dead source, reads
// incoming R27. Calls independently close their transitive bodies and kill
// this fact at the caller. Nothing about a callee's resulting address escapes.
func arm64ScratchNativeDoesNotAccess(body arm64ScratchNativeBody) bool {
	instructions, edges, valid := arm64ScratchNativeGraph(body)
	if !valid {
		return false
	}
	effects := make([]arm64ScratchInputEffect, len(instructions))
	for index, instruction := range instructions {
		effect, valid := arm64ScratchNativeEffect(instruction)
		if !valid {
			return false
		}
		effects[index].call = effect.call
		if effect.reads {
			effects[index].reads = 1 << 27
		}
		if effect.defines {
			effects[index].writes = 1 << 27
		}
	}
	return arm64ScratchNativeAvailable(effects, edges, 0)
}
