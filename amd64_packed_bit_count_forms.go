package plan9asm

import (
	"fmt"
	"strings"
)

type x86PackedBitCountForm struct {
	x86PackedBinaryForm
	spec amd64PackedBitCountSpec
}

// _yvexpandpd has the same EVEX source/width/mask axes as the shared binary
// grammar, without a second input. The local projection never rewrites source.
func x86PackedBitCountProperties(op Op, ins Instr, arch string) (x86PackedBitCountForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := amd64PackedBitCountSpecs[Op(base)]
	form := x86PackedBitCountForm{spec: spec}
	if !known {
		return form, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) || len(ins.Args) != 2 && len(ins.Args) != 3 {
		return form, true, fmt.Errorf("%s %s has an unbound dispatch or unary operand count: %q", arch, op, ins.Raw)
	}
	local := ins
	local.Op = op
	destination := ins.Args[len(ins.Args)-1]
	local.Args = []Operand{ins.Args[0], destination, destination}
	if len(ins.Args) == 3 {
		local.Args = []Operand{ins.Args[0], destination, ins.Args[1], destination}
	}
	local, contextual := x86VectorValueMemoryInput(local, arch)
	grammar := x86PackedBinarySpec{encoding: x86PackedLogicalEVEX, zeroing: true}
	if spec.broadcast {
		grammar.broadcastBytes = spec.laneBits / 8
	}
	var err error
	form.x86PackedBinaryForm, err = x86PackedBinaryOperandGrammar(local, arch, grammar, true)
	if err != nil {
		return form, true, err
	}
	form.second, form.destination = -1, len(ins.Args)-1
	if form.mask >= 0 {
		form.mask = 1
	}
	for _, operand := range ins.Args {
		if operand.Kind == OpReg && amd64VectorByteWidth(operand.Reg) != 0 &&
			!amd64GoPackedVectorMoveRegister(operand, form.byteWidth, arch) {
			return form, true, fmt.Errorf("%s %s has an unbound vector bank: %q", arch, op, ins.Raw)
		}
	}
	if form.memory >= 0 && !contextual && !x86PackedShiftMemoryValid(ins.Args[form.memory], arch) {
		return form, true, fmt.Errorf("%s %s has an unbound memory operand: %q", arch, op, ins.Raw)
	}
	if contextual {
		return form, true, x86VectorValueMemoryContext(ins)
	}
	return form, true, nil
}

func x86ResultPackedBitCountStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	form, known, err := x86PackedBitCountProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	return x86ResultFixedVectorInputs(ins, form.x86PackedBinaryForm, false, state, owned, arch), true
}
