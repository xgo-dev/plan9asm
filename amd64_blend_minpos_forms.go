package plan9asm

import (
	"fmt"
	"strings"
)

// These two Go tables share a full vector source and a vector output, not
// their data dependencies. Blends read one sign bit per mask lane and two
// possible data bytes; minimum-position reads all eight unsigned words.
// Neither the grammar nor a native address establishes initialized storage.
type x86BlendMinposForm struct {
	source, destination, mask, base int
	byteWidth, laneBits             int
	legacy, minimum                 bool
	memory                          bool
}

func x86BlendMinposProperties(op Op, ins Instr, arch string) (x86BlendMinposForm, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	blend, isBlend := amd64VariableBlendSpecs[Op(name)]
	minimum, isMinimum := amd64MinimumPositionSpecs[Op(name)]
	form := x86BlendMinposForm{source: 0, destination: 1, mask: -1, base: -1,
		byteWidth: 16, laneBits: 16, minimum: isMinimum}
	if !isBlend && !isMinimum {
		return form, false, nil
	}
	fail := func() (x86BlendMinposForm, bool, error) {
		return form, true, fmt.Errorf("%s %s outside Go blend/minimum-position operand grammar: %q", arch, op, ins.Raw)
	}
	if arch != "amd64" && arch != "386" || dotted ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return fail()
	}
	vector := isBlend && blend.vector || isMinimum && minimum.vector
	form.legacy = !vector
	if isBlend {
		form.source, form.mask, form.base, form.destination = 1, 0, 2, 2
		form.laneBits = blend.laneBits
		if vector {
			form.destination = 3
		}
	}
	if len(ins.Args) != form.destination+1 {
		return fail()
	}
	if arch == "386" && len(ins.Args) > 3 && !ins.x86Encoded {
		// The ordinary Go frontend cannot express this VEX form in mode32.
		// Only a validated physical decoder supplies its distinct grammar;
		// original bytes and all producer inputs still need whole replay.
		return fail()
	}
	form.byteWidth = amd64VectorByteWidth(ins.Args[form.destination].Reg)
	if form.byteWidth != 16 && (form.byteWidth != 32 || form.legacy || form.minimum) {
		return fail()
	}
	register := func(operand Operand) bool {
		if !vector {
			index, valid := amd64ParseXReg(operand.Reg)
			return operand.Kind == OpReg && valid && index < 16 && (arch != "386" || index < 8)
		}
		return amd64VEXVectorRegister(operand, form.byteWidth)
	}
	if !register(ins.Args[form.destination]) ||
		isBlend && (!register(ins.Args[form.mask]) || !register(ins.Args[form.base]) ||
			form.legacy && ins.Args[form.mask].Reg != "X0") {
		return fail()
	}
	source := ins.Args[form.source]
	form.memory = isAMD64MemoryOperand(source)
	if !register(source) && (!form.memory || !x86PackedShiftMemoryValid(source, arch)) {
		return fail()
	}
	return form, true, x86Mode32VectorRegisterContext(ins, arch)
}

func x86TypedBlendMinposByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86BlendMinposProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	effect := x86TypedByteEffect{requiresResultProof: true, operands: []x86TypedByteOperand{
		{index: form.source, operand: ins.Args[form.source], width: int64(form.byteWidth), read: true},
		{index: form.destination, operand: ins.Args[form.destination], width: int64(form.byteWidth), write: true},
	}}
	if !form.minimum {
		effect.operands = append(effect.operands,
			x86TypedByteOperand{index: form.mask, operand: ins.Args[form.mask], width: int64(form.byteWidth), read: true},
			x86TypedByteOperand{index: form.base, operand: ins.Args[form.base], width: int64(form.byteWidth), read: true})
	}
	return effect, true, nil
}
