package plan9asm

import (
	"fmt"
	"strings"
)

type x86MaskBlendForm struct {
	x86PackedBinaryForm
	spec amd64MaskBlendSpec
}

func x86MaskBlendProperties(op Op, ins Instr, arch string) (x86MaskBlendForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := amd64MaskBlendSpecs[Op(base)]
	result := x86MaskBlendForm{spec: spec}
	if !known {
		return result, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return result, true, fmt.Errorf("mask blend dispatch/source opcode mismatch")
	}
	grammar := x86PackedBinarySpec{encoding: x86PackedLogicalEVEX, zeroing: true}
	if spec.broadcast {
		grammar.broadcastBytes = spec.laneBits / 8
	}
	local := ins
	local.Op = op
	var err error
	// This shared validator describes only Go's operand and address grammar;
	// numerical bytes and native storage remain separate consumer obligations.
	result.x86PackedBinaryForm, err = x86ConflictFunnelOperandGrammar(local, arch, grammar, false)
	return result, true, err
}

// The K operand selects between two sources; it is not an old-destination
// merge. No mask selects only the first Plan 9 source, and .Z drops the second.
func x86TypedMaskBlendByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86MaskBlendProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	width, firstWidth := int64(form.byteWidth), int64(form.byteWidth)
	if form.memory >= 0 {
		firstWidth = int64(form.memoryBytes)
	}
	effect := x86TypedByteEffect{requiresResultProof: true, operands: []x86TypedByteOperand{
		{index: form.first, operand: ins.Args[form.first], width: firstWidth, read: true},
		{index: form.destination, operand: ins.Args[form.destination], width: width, write: true},
	}}
	if form.mask >= 0 {
		effect.operands = append(effect.operands,
			x86TypedByteOperand{index: form.mask, operand: ins.Args[form.mask], width: 8, read: true})
		if !form.zeroing {
			effect.operands = append(effect.operands,
				x86TypedByteOperand{index: form.second, operand: ins.Args[form.second], width: width, read: true})
		}
	}
	return effect, true, nil
}
