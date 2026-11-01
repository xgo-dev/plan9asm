package plan9asm

import (
	"fmt"
	"strings"
)

type x86PackedTestMaskForm struct {
	x86PackedBinaryForm
	spec   amd64PackedTestMaskSpec
	source Operand
}

// Source vectors, optional K input and K result are disjoint roles. The
// shared mask-result grammar grants no numerical bytes or memory backing.
func x86PackedTestMaskProperties(op Op, ins Instr, arch string) (x86PackedTestMaskForm, bool, error) {
	base, suffix, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := amd64PackedTestMaskSpecs[base]
	f := x86PackedTestMaskForm{spec: spec}
	if !known {
		return f, false, nil
	}
	fail := func() (x86PackedTestMaskForm, bool, error) {
		return f, true, fmt.Errorf("%s %s outside packed integer test-to-mask grammar: %q", arch, op, ins.Raw)
	}
	if arch != "amd64" && arch != "386" || ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return fail()
	}
	local := ins
	local.Op = op
	roles, valid := x86PackedMaskCompareProperties(local, arch, 0, spec.laneBits, dotted, suffix)
	if !valid {
		return fail()
	}
	f.x86PackedBinaryForm, f.source = roles, ins.Args[roles.first]
	for _, index := range []int{roles.first, roles.second} {
		arg := ins.Args[index]
		if arg.Kind == OpReg && !amd64GoPackedVectorMoveRegister(arg, roles.byteWidth, arch) {
			return fail()
		}
	}
	if roles.memory >= 0 && (ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride) {
		return f, true, fmt.Errorf("%w: test-to-mask has no bound address-size override", ErrProbeNeedsContext)
	}
	return f, true, nil
}

func x86TypedPackedTestMaskByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	f, known, err := x86PackedTestMaskProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	firstWidth := f.byteWidth
	if f.memory >= 0 {
		firstWidth = f.memoryBytes
	}
	effect := x86TypedByteEffect{requiresResultProof: true,
		vector: x86TypedVectorEffect{memoryAlignment: 1},
		operands: []x86TypedByteOperand{
			{index: f.first, operand: f.source, width: int64(firstWidth), read: true},
			{index: f.second, operand: ins.Args[f.second], width: int64(f.byteWidth), read: true},
			{index: f.destination, operand: ins.Args[f.destination], width: 8, write: true},
		}}
	if f.mask >= 0 {
		effect.operands = append(effect.operands, x86TypedByteOperand{index: f.mask, operand: ins.Args[f.mask], width: 8, read: true})
	}
	return effect, true, nil
}

func x86ResultPackedTestMaskStep(ins Instr, state *x86ResultState, owned []bool, arch string, native bool) (bool, bool) {
	f, known, err := x86PackedTestMaskProperties(ins.Op, ins, arch)
	if !known || err != nil || !x86ResultNamedPredicateInstruction(ins) {
		return false, known
	}
	if f.mask >= 0 {
		mask, _ := amd64ParseKReg(ins.Args[f.mask].Reg)
		if !state.masks[mask] {
			return false, true
		}
	}
	for _, index := range []int{f.first, f.second} {
		operand := ins.Args[index]
		if index == f.memory {
			if !x86ResultReadWithNativeContinuation(ins, operand, int64(f.memoryBytes), state, owned, arch, native) {
				return false, true
			}
			continue
		}
		vector, valid := amd64VectorRegisterIndex(operand.Reg, f.byteWidth)
		required := x86CallerVectorByteMask(int64(f.byteWidth))
		if !valid || state.vectorBytes(vector)&required != required {
			return false, true
		}
	}
	// Even equal source registers depend on their actual intersection bits.
	// Disabled and high K bits are written zero, never merged from old K.
	destination, _ := amd64ParseKReg(ins.Args[f.destination].Reg)
	state.masks[destination] = true
	return true, true
}
