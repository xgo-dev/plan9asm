package plan9asm

import (
	"fmt"
	"strings"
)

type x86GFNIForm struct {
	x86PackedBinaryForm
	spec      amd64GFNISpec
	immediate uint8
}

func x86GFNIProperties(op Op, ins Instr, arch string) (x86GFNIForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := amd64GFNISpecs[Op(base)]
	form := x86GFNIForm{spec: spec}
	if !known {
		return form, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return form, true, fmt.Errorf("GFNI dispatch/source opcode mismatch: %s/%s", op, ins.Op)
	}
	local := ins
	local.Op = op
	offset := 0
	if spec.immediate {
		if len(ins.Args) == 0 || !amd64UnsignedImmediate(ins.Args[0], 8) {
			return form, true, fmt.Errorf("%s %s requires a resolved unsigned imm8: %q", arch, op, ins.Raw)
		}
		if arch == "386" && !ins.x86Encoded {
			return form, true, fmt.Errorf("386 %s exceeds cmd/asm's named operand limit: %q", op, ins.Raw)
		}
		form.immediate, offset = uint8(ins.Args[0].Imm), 1
		local.Args = ins.Args[1:]
	}
	local, contextual := x86VectorValueMemoryInput(local, arch)
	grammar := x86PackedBinarySpec{encoding: x86PackedLogicalVEXOrEVEX, zeroing: true}
	if spec.broadcast {
		grammar.broadcastBytes = 8
	}
	var err error
	form.x86PackedBinaryForm, err = x86PackedBinaryOperandGrammar(local, arch, grammar, ins.x86Encoded)
	if err != nil {
		return form, true, err
	}
	form.first += offset
	form.second += offset
	form.destination += offset
	if form.mask >= 0 {
		form.mask += offset
	}
	if form.memory >= 0 {
		form.memory += offset
	}
	for _, operand := range ins.Args {
		if operand.Kind == OpReg && amd64VectorByteWidth(operand.Reg) != 0 &&
			!amd64GoPackedVectorMoveRegister(operand, form.byteWidth, arch) {
			return form, true, fmt.Errorf("%s %s has an unbound physical vector register: %q", arch, op, ins.Raw)
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

func x86ResultGFNIStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	form, known, err := x86GFNIProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	return x86ResultFixedVectorInputs(ins, form.x86PackedBinaryForm, false, state, owned, arch), true
}
