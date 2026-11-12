package plan9asm

import "strings"

// Validated legacy and non-masked VEX forms share source-width and dependency
// axes, not permission. The consumer selects its admitted generation first;
// legacy reads its old destination, VEX independently writes and clears it.
// A physical MMX source is supplied by the parser, never reinterpreted here.
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
	effect := x86TypedByteEffect{operands: make([]x86TypedByteOperand, count)}
	effect.operands[0] = x86TypedByteOperand{index: form.first, operand: source, width: sourceWidth, read: true}
	effect.operands[1] = x86TypedByteOperand{index: form.second, operand: ins.Args[form.second], width: width, read: true, write: form.legacy}
	if form.legacy && !form.mmx {
		effect.vector = x86TypedVectorEffect{x86TypedVectorUpperPreserve, width}
	} else if !form.legacy {
		effect.vector = x86TypedVectorEffect{x86TypedVectorUpperZero, 1}
		effect.operands[2] = x86TypedByteOperand{index: form.destination, operand: ins.Args[form.destination], width: width, write: true}
	}
	return effect
}

type x86PackedBinaryEffectForm struct {
	x86PackedBinaryForm
	source Operand // Retains the actual MMX bank of a legacy GP spelling.
	vex    bool
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
		return x86PackedBinaryEffectForm{form.x86PackedBinaryForm, form.source, false}, true, err
	}
	if form, known, err := x86PackedLowMultiplyProperties(op, ins, arch); known {
		var source Operand
		if err == nil {
			source = ins.Args[form.first]
		}
		return x86PackedBinaryEffectForm{form.x86PackedBinaryForm, source, form.spec.encoding != x86PackedLogicalEVEX}, true, err
	}
	form, known, err := x86PackedPhysicalProperties(op, ins, arch, "")
	return x86PackedBinaryEffectForm{form.x86PackedBinaryForm, form.source, true}, known, err
}
