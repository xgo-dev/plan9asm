package plan9asm

import (
	"fmt"
	"strings"
)

type x86SingleSourceNarrowForm struct {
	spec                                  amd64SingleSourceNarrowSpec
	inputBytes, outputBytes, carrierBytes int
	destination, mask, memory             int
	zeroing                               bool
}

func (f x86SingleSourceNarrowForm) undefinedOpcode() bool {
	return f.zeroing && f.memory >= 0
}

// Source capacity, active output tuple and physical destination carrier are
// separate axes. A form grants neither initialized bytes nor memory backing.
func x86SingleSourceNarrowProperties(op Op, ins Instr, arch string) (x86SingleSourceNarrowForm, bool, error) {
	name, suffix, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := amd64SingleSourceNarrowSpecs[name]
	f := x86SingleSourceNarrowForm{spec: spec, destination: len(ins.Args) - 1, mask: -1, memory: -1, zeroing: dotted}
	if !known {
		return f, false, nil
	}
	fail := func() (x86SingleSourceNarrowForm, bool, error) {
		return f, true, fmt.Errorf("%s %s outside single-source narrowing grammar: %q", arch, op, ins.Raw)
	}
	if arch != "amd64" && arch != "386" || ins.Op != "" && !strings.EqualFold(string(op), string(ins.Op)) ||
		dotted && suffix != "Z" || len(ins.Args) != 2 && len(ins.Args) != 3 {
		return fail()
	}
	f.inputBytes = amd64VectorByteWidth(ins.Args[0].Reg)
	if ins.Args[0].Kind != OpReg || !amd64GoPackedVectorMoveRegister(ins.Args[0], f.inputBytes, arch) {
		return fail()
	}
	f.outputBytes = f.inputBytes * spec.outputBits / spec.inputBits
	f.carrierBytes = 16
	if f.outputBytes > 16 {
		f.carrierBytes = 32
	}
	if len(ins.Args) == 3 {
		k, valid := amd64ParseKReg(ins.Args[1].Reg)
		if ins.Args[1].Kind != OpReg || !valid || k == 0 {
			return fail()
		}
		f.mask = 1
	}
	if dotted && f.mask < 0 {
		return fail()
	}
	destination := ins.Args[f.destination]
	if destination.Kind == OpReg {
		if !amd64GoPackedVectorMoveRegister(destination, f.carrierBytes, arch) {
			return fail()
		}
	} else {
		if !isAMD64MemoryOperand(destination) || !x86PackedShiftMemoryValid(destination, arch) {
			return fail()
		}
		f.memory = f.destination
	}
	return f, true, nil
}

func x86TypedSingleSourceNarrowByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	f, known, err := x86SingleSourceNarrowProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	if f.undefinedOpcode() {
		return x86TypedByteEffect{}, true, fmt.Errorf("%w: narrowing EVEX.z memory encoding has no ordinary byte continuation", ErrProbeNeedsContext)
	}
	width := f.carrierBytes
	if f.memory >= 0 {
		width = f.outputBytes
	}
	effect := x86TypedByteEffect{requiresResultProof: true,
		vector: x86TypedVectorEffect{x86TypedVectorUpperZero, 1},
		operands: []x86TypedByteOperand{
			{index: 0, operand: ins.Args[0], width: int64(f.inputBytes), read: true},
			{index: f.destination, operand: ins.Args[f.destination], width: int64(width), write: true,
				read: f.memory < 0 && f.mask >= 0 && !f.zeroing},
		}}
	if effect.operands[1].read {
		effect.operands[1].requiredBytes = x86CallerVectorByteMask(int64(f.outputBytes))
	}
	if f.mask >= 0 {
		effect.operands = append(effect.operands, x86TypedByteOperand{index: f.mask, operand: ins.Args[f.mask], width: 8, read: true})
	}
	return effect, true, nil
}

func x86ResultSingleSourceNarrowStep(ins Instr, state *x86ResultState, owned []bool, resultOffset int64,
	arch string, native bool) (bool, bool) {
	f, known, err := x86SingleSourceNarrowProperties(ins.Op, ins, arch)
	if !known || err != nil || f.undefinedOpcode() || !x86ResultNamedPredicateInstruction(ins) {
		return false, known
	}
	source, valid := amd64VectorRegisterIndex(ins.Args[0].Reg, f.inputBytes)
	required := x86CallerVectorByteMask(int64(f.inputBytes))
	if !valid || state.vectorBytes(source)&required != required {
		return false, true
	}
	if f.mask >= 0 {
		mask, _ := amd64ParseKReg(ins.Args[f.mask].Reg)
		if !state.masks[mask] {
			return false, true
		}
	}
	destination := ins.Args[f.destination]
	if f.memory >= 0 {
		if native && x86ResultIncomingPointerAddressIdentity(destination, state, arch) {
			return true, true // Paired store preserves faults, never establishes future NUM bytes.
		}
		if f.mask >= 0 && !x86ResultRead(destination, int64(f.outputBytes), state, owned, arch) {
			return false, true // Inactive logical result bytes must already be known.
		}
		return x86ResultStore(destination, int64(f.outputBytes), state, owned, resultOffset, arch), true
	}
	index, valid := amd64VectorRegisterIndex(destination.Reg, f.carrierBytes)
	old := x86CallerVectorByteMask(int64(f.outputBytes))
	if !valid || f.mask >= 0 && !f.zeroing && state.vectorBytes(index)&old != old {
		return false, true
	}
	state.writeVector(index, f.carrierBytes, ^uint64(0), false)
	return true, true
}
