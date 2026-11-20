package plan9asm

import (
	"fmt"
	"strings"
)

type x86PackedIntegerCompareSpec struct {
	laneBits int
	greater  bool
	legacy   bool
	mmx      bool
}

var x86PackedIntegerCompareSpecs = map[Op]x86PackedIntegerCompareSpec{
	"PCMPEQB":  {8, false, true, true},
	"PCMPEQW":  {16, false, true, true},
	"PCMPEQL":  {32, false, true, true},
	"PCMPEQQ":  {64, false, true, false},
	"PCMPGTB":  {8, true, true, true},
	"PCMPGTW":  {16, true, true, true},
	"PCMPGTL":  {32, true, true, true},
	"PCMPGTQ":  {64, true, true, false},
	"VPCMPEQB": {8, false, false, false},
	"VPCMPEQW": {16, false, false, false},
	"VPCMPEQD": {32, false, false, false},
	"VPCMPEQQ": {64, false, false, false},
	"VPCMPGTB": {8, true, false, false},
	"VPCMPGTW": {16, true, false, false},
	"VPCMPGTD": {32, true, false, false},
	"VPCMPGTQ": {64, true, false, false},
}

type x86PackedIntegerCompareForm struct {
	x86PackedBinaryForm
	spec       x86PackedIntegerCompareSpec
	source     Operand
	maskResult bool
}

// Integer relations of an identical physical vector view are independent of
// its bits, including all eight immediate predicates. This is only a numerical
// dependency rule after full grammar validation. Mask inputs remain required;
// floating comparisons, memory, raw roles and the native MMX bank stay separate.
func (form x86PackedIntegerCompareForm) identicalVectorInputs(ins Instr) bool {
	return x86ResultNamedPredicateInstruction(ins) && !form.mmx && form.memory < 0 &&
		form.source.Kind == OpReg && ins.Args[form.second].Kind == OpReg &&
		form.source.Reg == ins.Args[form.second].Reg
}

// Properties describe the Go operand rows and physical mode, not initialized
// inputs, native backing, memory bounds, or caller authority. The raw decoder's
// eight-entry encoding registry remains distinct from these sixteen Go names.
func x86PackedIntegerCompareProperties(op Op, ins Instr, arch string) (x86PackedIntegerCompareForm, bool, error) {
	base, suffix, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := x86PackedIntegerCompareSpecs[Op(base)]
	if !known {
		return x86PackedIntegerCompareForm{}, false, nil
	}
	form := x86PackedIntegerCompareForm{spec: spec}
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return form, true, fmt.Errorf("packed integer compare dispatch/source opcode mismatch: %s/%s", op, ins.Op)
	}
	local := ins
	local.Op = op
	local.Args = append([]Operand(nil), ins.Args...)
	fail := func() (x86PackedIntegerCompareForm, bool, error) {
		return form, true, fmt.Errorf("%s %s operands/suffix outside Go packed integer compare grammar: %q", arch, op, ins.Raw)
	}
	if arch != "amd64" && arch != "386" {
		return fail()
	}
	if spec.legacy || len(local.Args) == 3 && local.Args[2].Kind == OpReg && !amd64IsKOperand(local.Args[2]) {
		encoding := x86PackedLogicalVEX
		if spec.legacy {
			encoding = x86PackedLogicalLegacyFP
			if spec.mmx {
				encoding = x86PackedLogicalLegacyInteger
				var err error
				local, err = x86LegacyMMXReadInstruction(local, arch)
				if err != nil {
					return form, true, err
				}
			}
		}
		binary, err := x86PackedBinaryProperties(local, arch, x86PackedBinarySpec{encoding: encoding})
		form.x86PackedBinaryForm = binary
		if err != nil {
			return form, true, err
		}
	} else {
		// _yvpcmpeqb EVEX rows produce K0-7, not an X/Y/Z destination;
		// their optional input mask is K1-7. There is no .Z form.
		form.maskResult = true
		binary, valid := x86PackedMaskCompareProperties(local, arch, 0, spec.laneBits, dotted, suffix)
		if !valid {
			return fail()
		}
		form.x86PackedBinaryForm = binary
	}
	form.source = local.Args[form.first]
	if err := x86Mode32VectorRegisterContext(local, arch); err != nil {
		return form, true, err
	}
	if form.memory >= 0 && (ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride) {
		return form, true, fmt.Errorf("%w: packed integer compare has no bound address-size override", ErrProbeNeedsContext)
	}
	return form, true, nil
}

// The EVEX K-result rows of _yvpcmpeqb and _yvpcmpb have the same source,
// width, mask and broadcast axes. Only the latter has a leading immediate.
// This descriptor supplies operand roles, never initialized data or backing.
func x86PackedMaskCompareProperties(ins Instr, arch string, first, laneBits int, dotted bool, suffix string) (x86PackedBinaryForm, bool) {
	form := x86PackedBinaryForm{first: first, second: first + 1, destination: len(ins.Args) - 1, mask: -1, memory: -1}
	if len(ins.Args) != first+3 && len(ins.Args) != first+4 || dotted && suffix != "BCST" {
		return form, false
	}
	if !amd64IsKOperand(ins.Args[form.destination]) {
		return form, false
	}
	width, valid := amd64PackedCompareWidth(ins.Args[form.second])
	if !valid || !amd64GoPackedVectorMoveRegister(ins.Args[form.second], width, "amd64") {
		return form, false
	}
	form.byteWidth = width
	source := ins.Args[first]
	if source.Kind == OpReg {
		if !amd64GoPackedVectorMoveRegister(source, width, "amd64") {
			return form, false
		}
	} else if !x86PackedShiftMemoryValid(source, arch) {
		return form, false
	} else {
		form.memory, form.memoryBytes = first, width
	}
	if dotted {
		if laneBits < 32 || form.memory < 0 {
			return form, false
		}
		form.broadcast, form.memoryBytes = true, laneBits/8
	}
	if len(ins.Args) == first+4 {
		mask := first + 2
		if !amd64NonzeroKOperand(ins.Args[mask]) || arch == "386" && !ins.x86Encoded && ins.x86SourceRaw == nil {
			return form, false
		}
		form.mask = mask
	}
	return form, true
}

func x86TypedPackedIntegerCompareByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86PackedIntegerCompareProperties(op, ins, arch)
	immediateFamily := false
	if !known {
		immediate, recognized, immediateErr := x86ImmediatePackedCompareProperties(op, ins, arch)
		form, known, err = immediate.x86PackedIntegerCompareForm, recognized, immediateErr
		immediateFamily = recognized
	}
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	firstWidth := form.byteWidth
	if form.memory >= 0 {
		firstWidth = form.memoryBytes
	}
	readInputs := !form.identicalVectorInputs(ins)
	operands := []x86TypedByteOperand{
		{index: form.first, operand: form.source, width: int64(firstWidth), read: readInputs},
		{index: form.second, operand: ins.Args[form.second], width: int64(form.byteWidth), read: readInputs},
	}
	if form.mask >= 0 {
		operands = append(operands, x86TypedByteOperand{index: form.mask, operand: ins.Args[form.mask], width: 8, read: true})
	}
	width := form.byteWidth
	if form.maskResult {
		width = 8
	}
	operands = append(operands, x86TypedByteOperand{
		index: form.destination, operand: ins.Args[form.destination], width: int64(width), write: true,
	})
	effect := x86TypedByteEffect{operands: operands, requiresResultProof: immediateFamily}
	if !form.mmx && !form.maskResult {
		effect.vector.upperWrite = x86TypedVectorUpperZero
		effect.vector.memoryAlignment = 1
		if form.spec.legacy {
			effect.vector.upperWrite = x86TypedVectorUpperPreserve
			effect.vector.memoryAlignment = 16
		}
	}
	return effect, true, nil
}
