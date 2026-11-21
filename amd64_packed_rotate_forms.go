package plan9asm

import (
	"fmt"
	"strings"
)

type x86PackedRotateForm struct {
	x86PackedBinaryForm
	spec      amd64PackedRotateSpec
	immediate uint8
}

// Go's _yvprold and _yvblendmpd differ only in the count/data role. Both
// retain the shared EVEX width, register, mask and scalar-broadcast grammar.
func x86PackedRotateProperties(op Op, ins Instr, arch string) (x86PackedRotateForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := amd64PackedRotateSpecs[Op(base)]
	form := x86PackedRotateForm{spec: spec}
	if !known {
		return form, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) || len(ins.Args) != 3 && len(ins.Args) != 4 {
		return form, true, fmt.Errorf("%s %s has an unbound dispatch or operand count", arch, op)
	}
	local := ins
	local.Op = op
	if !spec.variable {
		if !amd64UnsignedImmediate(ins.Args[0], 8) || ins.Args[0].ImmIsFloat || ins.Args[0].ImmRaw != "" {
			return form, true, fmt.Errorf("%s %s requires the original unsigned imm8", arch, op)
		}
		form.immediate = uint8(ins.Args[0].Imm)
		destination := ins.Args[len(ins.Args)-1]
		// The extra destination exists only for unary shape validation. It
		// never becomes a numerical input to the immediate operation.
		local.Args = []Operand{ins.Args[1], destination, destination}
		if len(ins.Args) == 4 {
			local.Args = []Operand{ins.Args[1], destination, ins.Args[2], destination}
		}
	}
	var err error
	form.x86PackedBinaryForm, err = x86ConflictFunnelOperandGrammar(local, arch,
		x86PackedBinarySpec{encoding: x86PackedLogicalEVEX, broadcastBytes: spec.laneBits / 8, zeroing: true}, false)
	if !spec.variable {
		form.first, form.second, form.destination = 1, -1, len(ins.Args)-1
		if form.memory >= 0 {
			form.memory = 1
		}
	}
	return form, true, err
}

func x86TypedPackedRotateByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86PackedRotateProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	return x86TypedFixedVectorInputs(ins, form.x86PackedBinaryForm, false), true, nil
}
