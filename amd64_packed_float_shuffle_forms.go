package plan9asm

import (
	"fmt"
	"strings"
)

type x86PackedFloatShuffleForm struct {
	x86PackedBinaryForm
	bits     int
	selector uint8
}

// Go's two yxshuf rows and complete _yvgf2p8affineinvqb rows share the
// existing binary operand grammar. Only the selector and two-source byte
// dependencies differ from the single-source immediate integer shuffles.
func x86PackedFloatShuffleProperties(op Op, ins Instr, arch string) (x86PackedFloatShuffleForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	bits, vector, known := amd64PackedFloatShuffleProperties(base)
	f := x86PackedFloatShuffleForm{bits: bits}
	if !known {
		return f, false, nil
	}
	if arch == "" {
		arch = "amd64"
	}
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) ||
		len(ins.Args) < 3 || len(ins.Args) > 5 || arch == "386" && vector {
		return f, true, fmt.Errorf("%s %s has an unbound dispatch or Go operand arity", arch, op)
	}
	immediate, integer := x86ImmediateShuffleConstant(ins.Args[0], arch, ins.x86Encoded)
	if !integer || !amd64UnsignedImmediate(immediate, 8) {
		return f, true, fmt.Errorf("%s %s requires Go's resolved Yu8 immediate", arch, op)
	}
	spec := x86PackedBinarySpec{encoding: x86PackedLogicalLegacyFP}
	if vector {
		spec = x86PackedBinarySpec{encoding: x86PackedLogicalVEXOrEVEX, broadcastBytes: bits / 8, zeroing: true}
	}
	local := ins
	local.Op, local.Args = op, ins.Args[1:]
	var err error
	f.x86PackedBinaryForm, err = x86ConflictFunnelOperandGrammar(local, arch, spec, false)
	f.first++
	f.second++
	f.destination++
	if f.memory >= 0 {
		f.memory++
	}
	if f.mask >= 0 {
		f.mask++
	}
	f.selector = uint8(immediate.Imm)
	return f, true, err
}

// Index the concatenation of Go's first and second sources. PS selects its
// low pair from the second source; PD alternates second/first within each
// 128-bit lane, using a distinct immediate bit for every output qword.
func (f x86PackedFloatShuffleForm) sourceByte(output int) int {
	bytes := f.bits / 8
	lane := output / bytes
	first := lane%4 >= 2
	selected := int(f.selector>>uint(2*(lane%4))) & 3
	if f.bits == 64 {
		first = lane%2 != 0
		selected = int(f.selector>>uint(lane)) & 1
	}
	at := output/16*16 + selected*bytes + output%bytes
	if first {
		if f.broadcast {
			at %= bytes
		}
		return at
	}
	return f.byteWidth + at
}

func (f x86PackedFloatShuffleForm) definedBytes(first, second, old uint64) uint64 {
	var defined uint64
	for output := 0; output < f.byteWidth; output++ {
		at := f.sourceByte(output)
		input := first
		if at >= f.byteWidth {
			input, at = second, at-f.byteWidth
		}
		known := input>>uint(at)&1 != 0
		if f.mask >= 0 && !f.zeroing {
			known = known && old>>uint(output)&1 != 0
		}
		if known {
			defined |= uint64(1) << uint(output)
		}
	}
	return defined
}

func x86TypedPackedFloatShuffleByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	f, known, err := x86PackedFloatShuffleProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	width, firstWidth := int64(f.byteWidth), int64(f.byteWidth)
	if f.memory >= 0 {
		firstWidth = int64(f.memoryBytes)
	}
	effect := x86TypedByteEffect{requiresResultProof: true, operands: []x86TypedByteOperand{
		{index: f.first, operand: ins.Args[f.first], width: firstWidth, read: true},
		{index: f.second, operand: ins.Args[f.second], width: width, read: true},
	}}
	if f.legacy {
		effect.operands[1].write = true
	} else {
		effect.operands = append(effect.operands, x86TypedByteOperand{
			index: f.destination, operand: ins.Args[f.destination], width: width, write: true,
			read: f.mask >= 0 && !f.zeroing,
		})
	}
	if f.mask >= 0 {
		effect.operands = append(effect.operands,
			x86TypedByteOperand{index: f.mask, operand: ins.Args[f.mask], width: 8, read: true})
	}
	return effect, true, nil
}
