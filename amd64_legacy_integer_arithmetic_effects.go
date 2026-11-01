package plan9asm

import (
	"fmt"
	"strings"
)

type x86LegacyIntegerArithmeticForm struct {
	x86PackedBinaryForm
	source, destination Operand
}

// Reuse the arithmetic specifications and Go operand rows already owned by
// lowering. This descriptor adds no frame, source, caller or initialized bank.
func x86LegacyIntegerArithmeticProperties(op Op, ins Instr, arch string) (x86LegacyIntegerArithmeticForm, bool, error) {
	name, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, add := amd64PackedAddSpecs[Op(name)]
	_, _, vector, subtract := amd64PackedSubtractProperties(name)
	if add && spec.form == amd64PackedAddVEXEVEX || subtract && vector || !add && !subtract {
		return x86LegacyIntegerArithmeticForm{}, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return x86LegacyIntegerArithmeticForm{}, true, fmt.Errorf("legacy integer arithmetic dispatch/source mismatch: %s/%s", op, ins.Op)
	}
	local := ins
	local.Op = op
	local.Args = append([]Operand(nil), ins.Args...)
	encoding := x86PackedLogicalLegacyFP
	if add && spec.form == amd64PackedAddLegacyYMM {
		encoding = x86PackedLogicalLegacyInteger
	}
	if encoding == x86PackedLogicalLegacyInteger {
		var err error
		local, err = x86LegacyMMXReadInstruction(local, arch)
		if err != nil {
			return x86LegacyIntegerArithmeticForm{}, true, err
		}
	}
	form, err := x86PackedBinaryProperties(local, arch, x86PackedBinarySpec{encoding: encoding})
	result := x86LegacyIntegerArithmeticForm{x86PackedBinaryForm: form}
	if err == nil {
		result.source, result.destination = local.Args[0], local.Args[1]
	}
	return result, true, err
}

func x86LegacyIntegerArithmeticEmitterContext(form x86LegacyIntegerArithmeticForm, ins Instr) error {
	if form.mmx && ins.Args[0].Kind == OpReg && ins.Args[0].Reg != form.source.Reg {
		return fmt.Errorf("%w: legacy integer arithmetic GP spelling encodes an MMX source without its physical bank transport", ErrProbeNeedsContext)
	}
	return nil
}
