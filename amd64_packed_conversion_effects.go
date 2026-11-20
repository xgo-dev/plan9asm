package plan9asm

import (
	"fmt"
	"strings"
)

func x86TypedPackedConversionByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if _, known := x86PackedConversionSpecification(Op(base)); !known {
		return x86TypedByteEffect{}, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(op), string(ins.Op)) {
		return x86TypedByteEffect{}, true, fmt.Errorf("packed conversion effect/source mismatch")
	}
	ins.Op = op
	f, known, err := x86PackedConversionProperties(ins, arch)
	if err != nil {
		return x86TypedByteEffect{}, known, err
	}
	width := f.inputBytes
	if f.memory >= 0 {
		width = f.memoryBytes
	}
	effect := x86TypedByteEffect{operands: []x86TypedByteOperand{
		{index: 0, operand: ins.Args[0], width: int64(width), read: true},
		{index: f.destination, operand: ins.Args[f.destination], width: int64(f.shape.destinationBytes), write: true},
	}}
	if f.mask >= 0 {
		effect.operands = append(effect.operands, x86TypedByteOperand{index: f.mask, operand: ins.Args[f.mask], width: 8, read: true})
		if !f.properties.zeroing {
			effect.operands = append(effect.operands, x86TypedByteOperand{index: f.destination, operand: ins.Args[f.destination],
				width: int64(f.shape.lanes * f.spec.destinationBits / 8), read: true})
		}
	}
	return effect, true, nil // Integer FLAGS do not change; MXCSR remains native.
}

func x86ResultPackedConversionStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	return x86ResultPackedConversionStepWithRead(ins, state, owned, arch, false)
}

// The native conversion emitter retains the complete opcode's access and
// MXCSR effects. This continuation grants no caller or pointee facts.
func x86ResultPackedConversionStepWithRead(ins Instr, state *x86ResultState, owned []bool,
	arch string, nativeRead bool) (bool, bool) {
	f, known, err := x86PackedConversionProperties(ins, arch)
	if !known {
		return false, false
	}
	if err != nil || f.mmx || !x86ResultNamedPredicateInstruction(ins) {
		return false, true
	}
	return x86ResultPackedConversionInputs(ins, f, state, owned, arch, nativeRead), true
}

// The caller selects and authenticates its own family before sharing these
// lane/input dependencies. No source or native-read capability follows.
func x86ResultPackedConversionInputs(ins Instr, f x86PackedConversionForm, state *x86ResultState, owned []bool,
	arch string, nativeRead bool) bool {
	if f.mask >= 0 {
		index, valid := amd64ParseKReg(ins.Args[f.mask].Reg)
		if !valid || !state.masks[index] {
			return false
		}
	}
	if f.memory >= 0 {
		if !x86ResultReadWithNativeContinuation(ins, ins.Args[0], int64(f.memoryBytes), state, owned, arch, nativeRead) {
			return false
		}
	} else {
		index, _ := amd64VectorRegisterIndex(ins.Args[0].Reg, f.shape.sourceBytes)
		input := x86CallerVectorByteMask(int64(f.inputBytes))
		if state.vectorBytes(index)&input != input {
			return false
		}
	}
	index, _ := amd64VectorRegisterIndex(ins.Args[f.destination].Reg, f.shape.destinationBytes)
	active := x86CallerVectorByteMask(int64(f.shape.lanes * f.spec.destinationBits / 8))
	if f.mask >= 0 && !f.properties.zeroing && state.vectorBytes(index)&active != active {
		return false
	}
	state.writeVector(index, f.shape.destinationBytes, x86CallerVectorByteMask(int64(f.shape.destinationBytes)), f.spec.legacy)
	return true
}

func x86CallerPackedConversionStep(ins *Instr, f x86PackedConversionForm, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	if f.mmx || f.mask >= 0 && !state.masks[ins.Args[f.mask].Reg] {
		return false
	}
	if f.memory >= 0 {
		source := ins.Args[0]
		if source.Kind == OpFP || source.Kind == OpMem &&
			(source.Mem.Base == SP || source.Mem.Base == BP || source.Mem.Index == BP) {
			return false
		}
		if !x86CallerOrdinaryMemoryStep(ins, f.memory, state, proof, int64(f.memoryBytes), false) {
			return false
		}
	} else {
		input := x86CallerVectorByteMask(int64(f.inputBytes))
		if state.vectors[x86CallerVectorRoot(ins.Args[0].Reg)]&input != input {
			return false
		}
	}
	destination := x86CallerVectorRoot(ins.Args[f.destination].Reg)
	active := x86CallerVectorByteMask(int64(f.shape.lanes * f.spec.destinationBits / 8))
	if f.mask >= 0 && !f.properties.zeroing && state.vectors[destination]&active != active {
		return false
	}
	if f.spec.legacy {
		state.vectors[destination] |= x86CallerVectorByteMask(int64(f.shape.destinationBytes))
	} else {
		state.vectors[destination] = ^uint64(0)
	}
	return true
}
