package plan9asm

import (
	"fmt"
	"strings"
)

type x86PackedAlignSpec struct {
	x86PackedBinarySpec
	bits int
}

// The immediate and selector differ; operand widths, masks and original
// memory envelopes use the same complete binary grammar as other families.
var x86PackedAlignSpecs = map[Op]x86PackedAlignSpec{
	"PALIGNR":  {x86PackedBinarySpec: x86PackedBinarySpec{encoding: x86PackedLogicalLegacyFP}, bits: 8},
	"VPALIGNR": {x86PackedBinarySpec: x86PackedBinarySpec{encoding: x86PackedLogicalVEXOrEVEX, zeroing: true}, bits: 8},
	"VALIGND":  {x86PackedBinarySpec: x86PackedBinarySpec{encoding: x86PackedLogicalEVEX, broadcastBytes: 4, zeroing: true}, bits: 32},
	"VALIGNQ":  {x86PackedBinarySpec: x86PackedBinarySpec{encoding: x86PackedLogicalEVEX, broadcastBytes: 8, zeroing: true}, bits: 64},
}

type x86PackedAlignForm struct {
	x86PackedBinaryForm
	spec      x86PackedAlignSpec
	immediate uint8
}

func x86PackedAlignProperties(op Op, ins Instr, arch string) (x86PackedAlignForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := x86PackedAlignSpecs[Op(base)]
	result := x86PackedAlignForm{spec: spec}
	if !known {
		return result, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) ||
		len(ins.Args) < 3 || len(ins.Args) > 5 || arch == "386" && spec.encoding != x86PackedLogicalLegacyFP {
		return result, true, fmt.Errorf("%s %s has an unbound dispatch or named operand arity", arch, op)
	}
	immediate, integer := x86ImmediateShuffleConstant(ins.Args[0], arch, ins.x86Encoded)
	if !integer || !amd64UnsignedImmediate(immediate, 8) {
		return result, true, fmt.Errorf("%s %s requires Go's complete Yu8 immediate class", arch, op)
	}
	local := ins
	local.Op, local.Args = op, ins.Args[1:]
	var err error
	result.x86PackedBinaryForm, err = x86ConflictFunnelOperandGrammar(local, arch, spec.x86PackedBinarySpec, false)
	result.first++
	result.second++
	result.destination++
	if result.memory >= 0 {
		result.memory++
	}
	if result.mask >= 0 {
		result.mask++
	}
	result.immediate = uint8(immediate.Imm)
	return result, true, err
}

// Return a byte in the first/second concatenated vectors, or -1 for a known
// zero. PALIGNR is lane-local and saturates; VALIGN wraps its element count
// and crosses the complete physical vector, not each 128-bit lane.
func (f x86PackedAlignForm) sourceByte(output int) int {
	if f.spec.bits == 8 {
		selected := output%16 + int(f.immediate)
		if selected >= 32 {
			return -1
		}
		if selected < 16 {
			return output/16*16 + selected
		}
		return f.byteWidth + output/16*16 + selected - 16
	}
	bytes := f.spec.bits / 8
	count := int(f.immediate) & (f.byteWidth/bytes - 1)
	return (output/bytes+count)*bytes + output%bytes
}

func (f x86PackedAlignForm) definedBytes(first, second, old uint64) uint64 {
	var defined uint64
	for output := 0; output < f.byteWidth; output++ {
		at, known := f.sourceByte(output), false
		if at < 0 {
			known = true
		} else if at < f.byteWidth {
			known = first>>uint(at)&1 != 0
		} else {
			known = second>>uint(at-f.byteWidth)&1 != 0
		}
		if f.mask >= 0 && !f.zeroing {
			known = known && old>>uint(output)&1 != 0
		}
		if known {
			defined |= uint64(1) << uint(output)
		}
	}
	return defined
}

func x86TypedPackedAlignByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86PackedAlignProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	width, firstWidth := int64(form.byteWidth), int64(form.byteWidth)
	if form.memory >= 0 {
		firstWidth = int64(form.memoryBytes)
	}
	effect := x86TypedByteEffect{
		requiresResultProof: x86ResultNamedPredicateInstruction(ins),
		operands: []x86TypedByteOperand{
			{index: form.first, operand: ins.Args[form.first], width: firstWidth, read: true},
			{index: form.second, operand: ins.Args[form.second], width: width, read: true},
			{index: form.destination, operand: ins.Args[form.destination], width: width,
				read: form.mask >= 0 && !form.zeroing, write: true},
		},
	}
	if form.mask >= 0 {
		effect.operands = append(effect.operands,
			x86TypedByteOperand{index: form.mask, operand: ins.Args[form.mask], width: 8, read: true})
	}
	return effect, true, nil
}
