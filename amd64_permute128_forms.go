package plan9asm

import (
	"fmt"
	"strings"
)

// Both _yvperm2f128 members have the same fixed VEX.256.W0 grammar and
// bit-selection semantics. Their different native CPUID requirements are not
// numerical input, memory or source permissions.
var x86Permute128Specs = map[Op]byte{
	"VPERM2F128": 0x06,
	"VPERM2I128": 0x46,
}

type x86Permute128Form struct {
	x86PackedBinaryForm
	immediate uint8
}

func x86Permute128Properties(op Op, ins Instr, arch string) (x86Permute128Form, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	_, known := x86Permute128Specs[Op(base)]
	result := x86Permute128Form{}
	if !known {
		return result, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) || len(ins.Args) != 4 ||
		arch == "386" && !(ins.x86Encoded && ins.x86Permute128VEX) {
		return result, true, fmt.Errorf("%s %s has an unbound dispatch or named four-operand role", arch, op)
	}
	immediate, integer := x86ImmediateShuffleConstant(ins.Args[0], arch, ins.x86Encoded)
	if !integer || !amd64UnsignedImmediate(immediate, 8) {
		return result, true, fmt.Errorf("%s requires Go's complete Yu8 immediate class", op)
	}
	local := ins
	local.Op, local.Args = op, ins.Args[1:]
	form, err := x86ConflictFunnelOperandGrammar(local, arch,
		x86PackedBinarySpec{encoding: x86PackedLogicalVEX}, false)
	form.first++
	form.second++
	form.destination++
	if form.memory >= 0 {
		form.memory++
	}
	result.x86PackedBinaryForm, result.immediate = form, uint8(immediate.Imm)
	if err == nil && form.byteWidth != 32 {
		err = fmt.Errorf("%s requires exactly VEX.256 operands", op)
	}
	return result, true, err
}

// Return one byte in the two Plan9 sources, or -1 for an immediate zero.
// Intel SRC1 is Plan9 source two. Selector bits 2 and 6 have no effect.
func (form x86Permute128Form) sourceByte(output int) int {
	control := form.immediate >> uint(output/16*4)
	if control&8 != 0 {
		return -1
	}
	selected := int(control & 3)
	source := 32
	if selected >= 2 {
		source = 0
	}
	return source + selected%2*16 + output%16
}

func (form x86Permute128Form) inputsDefined(first, second uint64) bool {
	for output := 0; output < 32; output++ {
		selected := form.sourceByte(output)
		if selected < 0 {
			continue
		}
		known := first
		if selected >= 32 {
			known, selected = second, selected-32
		}
		if known>>uint(selected)&1 == 0 {
			return false
		}
	}
	return true
}

func x86TypedPermute128ByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86Permute128Properties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	return x86TypedByteEffect{requiresResultProof: true, operands: []x86TypedByteOperand{
		{index: form.first, operand: ins.Args[form.first], width: 32, read: true},
		{index: form.second, operand: ins.Args[form.second], width: 32, read: true},
		{index: form.destination, operand: ins.Args[form.destination], width: 32, write: true},
	}}, true, nil
}
