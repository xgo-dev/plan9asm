package plan9asm

import "strings"

// Validated packed forms share source-width and dependency axes. Legacy
// preserves its upper alias, and VEX/EVEX clears it. EVEX merges read the
// active-width destination before writing it.
func x86PackedBinaryDependencyEffect(ins Instr, form x86PackedBinaryForm, source Operand) x86TypedByteEffect {
	width := int64(form.byteWidth)
	sourceWidth := width
	if form.memory >= 0 {
		sourceWidth = int64(form.memoryBytes)
	}
	count := 2
	if !form.legacy {
		count = 3
	}
	capacity := count
	if form.mask >= 0 {
		capacity++
	}
	effect := x86TypedByteEffect{operands: make([]x86TypedByteOperand, count, capacity)}
	effect.operands[0] = x86TypedByteOperand{index: form.first, operand: source, width: sourceWidth, read: true}
	effect.operands[1] = x86TypedByteOperand{index: form.second, operand: ins.Args[form.second], width: width, read: true, write: form.legacy}
	if form.legacy && !form.mmx {
		effect.vector = x86TypedVectorEffect{x86TypedVectorUpperPreserve, width}
	} else if !form.legacy {
		effect.vector = x86TypedVectorEffect{x86TypedVectorUpperZero, 1}
		effect.operands[2] = x86TypedByteOperand{index: form.destination, operand: ins.Args[form.destination], width: width, write: true}
	}
	effect.addWritemask(ins, form.mask, form.zeroing)
	return effect
}

// The destination is the last dependency of a packed vector-producing form.
// The bound proof tracks defined mask bits without assuming their values.
func (effect *x86TypedByteEffect) addWritemask(ins Instr, mask int, zeroing bool) {
	if mask < 0 {
		return
	}
	effect.operands[len(effect.operands)-1].read = !zeroing
	effect.operands = append(effect.operands, x86TypedByteOperand{
		index: mask, operand: ins.Args[mask], width: 8, read: true,
	})
}

// A packed K result defines the entire register. The optional writemask
// is an independent input even when it uses the same K register.
func x86PackedMaskResultEffect(ins Instr, form x86PackedBinaryForm, source Operand, readInputs bool) x86TypedByteEffect {
	width, sourceWidth := int64(form.byteWidth), int64(form.byteWidth)
	if form.memory >= 0 {
		sourceWidth = int64(form.memoryBytes)
	}
	effect := x86TypedByteEffect{
		vector: x86TypedVectorEffect{x86TypedVectorNoWrite, 1},
		operands: []x86TypedByteOperand{
			{index: form.first, operand: source, width: sourceWidth, read: readInputs},
			{index: form.second, operand: ins.Args[form.second], width: width, read: readInputs},
			{index: form.destination, operand: ins.Args[form.destination], width: 8, write: true},
		},
	}
	if form.mask >= 0 {
		effect.operands = append(effect.operands, x86TypedByteOperand{
			index: form.mask, operand: ins.Args[form.mask], width: 8, read: true,
		})
	}
	return effect
}

type x86PackedBinaryEffectForm struct {
	x86PackedBinaryForm
	source Operand // Retains the actual MMX bank of a legacy GP spelling.
}

// Keep the existing family parsers as the only opcode/form authority. This
// grouping adds no VEX, mask, broadcast, initialized input or memory backing.
func x86PackedBinaryByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	if effect, known, err := x86TypedLegacyLogicalByteEffect(op, ins, arch); known {
		return effect, true, err
	}
	if effect, known, err := x86TypedByteShuffleEffect(op, ins, arch); known {
		return effect, true, err
	}
	if effect, known, err := x86TypedImmediateShuffleByteEffect(op, ins, arch); known {
		return effect, true, err
	}
	if effect, known, err := x86TypedLegacyCLMULByteEffect(op, ins, arch); known {
		return effect, true, err
	}
	if effect, known, err := x86TypedLegacyPackedShiftByteEffect(op, ins, arch); known {
		return effect, true, err
	}
	form, known, err := x86PackedBinaryEffectProperties(op, ins, arch)
	if !known || err != nil || !form.legacy {
		return x86TypedByteEffect{}, known && (err != nil || form.legacy), err
	}
	return x86PackedBinaryDependencyEffect(ins, form.x86PackedBinaryForm, form.source), true, nil
}

func x86PackedBinaryEffectProperties(op Op, ins Instr, arch string) (x86PackedBinaryEffectForm, bool, error) {
	name := strings.ToUpper(string(op))
	if !strings.HasPrefix(name, "P") && !strings.HasPrefix(name, "VP") {
		return x86PackedBinaryEffectForm{}, false, nil // Negative filter only; the specs below remain authoritative.
	}
	if form, known, err := x86LegacyIntegerArithmeticProperties(op, ins, arch); known {
		return x86PackedBinaryEffectForm{form.x86PackedBinaryForm, form.source}, true, err
	}
	if form, known, err := x86PackedLowMultiplyProperties(op, ins, arch); known {
		var source Operand
		if err == nil {
			source = ins.Args[form.first]
		}
		return x86PackedBinaryEffectForm{form.x86PackedBinaryForm, source}, true, err
	}
	form, known, err := x86PackedPhysicalProperties(op, ins, arch, "")
	return x86PackedBinaryEffectForm{form.x86PackedBinaryForm, form.source}, known, err
}
