package plan9asm

import (
	"fmt"
	"strings"
)

type x86ScalarPrecisionSpec struct {
	inputBits, outputBits int
	legacy                bool
}

// Input and output precision are independent. In particular, a copied upper
// starts after the output scalar, while the memory tuple has the input width.
var x86ScalarPrecisionSpecs = map[Op]x86ScalarPrecisionSpec{
	"CVTSS2SD": {32, 64, true}, "CVTSD2SS": {64, 32, true},
	"VCVTSS2SD": {32, 64, false}, "VCVTSD2SS": {64, 32, false},
}

type x86ScalarPrecisionForm struct {
	x86FloatBinaryForm
	spec x86ScalarPrecisionSpec
	sae  bool
}

// Generation is a native ISA restriction, not numerical-input authority.
// Plain low-bank physical EVEX must not silently become its VEX spelling.
func x86ScalarPrecisionNativeEVEX(ins Instr, form x86ScalarPrecisionForm) bool {
	if form.spec.legacy {
		return false
	}
	if ins.x86ScalarPrecisionEVEX || form.mask >= 0 || form.sae || form.rounding != "" {
		return true
	}
	for _, operand := range ins.Args {
		if index, vector := amd64ParseXReg(operand.Reg); operand.Kind == OpReg && vector && index >= 16 {
			return true
		}
	}
	return false
}

func x86ScalarPrecisionProperties(op Op, ins Instr, arch string) (x86ScalarPrecisionForm, bool, error) {
	base, suffix, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := x86ScalarPrecisionSpecs[Op(base)]
	form := x86ScalarPrecisionForm{spec: spec}
	if !known {
		return form, false, nil
	}
	controls, valid := parseAMD64BinaryFloatingSuffix(suffix)
	if !valid || dotted && suffix == "" || spec.legacy && dotted || controls.broadcast ||
		controls.sae && spec.inputBits != 32 || controls.rounding != "" && spec.inputBits != 64 ||
		ins.Op != "" && !strings.EqualFold(string(op), string(ins.Op)) {
		return form, true, fmt.Errorf("%s %s outside Go scalar precision controls: %q", arch, op, ins.Raw)
	}
	// Only the complete operand axes are projected. The original opcode and
	// control are retained by this form and by every numerical/native consumer.
	local, contextual := x86VectorValueMemoryInput(ins, arch)
	local.Op = Op(base)
	if controls.zeroing {
		local.Op += ".Z"
	}
	var err error
	form.x86FloatBinaryForm, err = x86FloatBinaryOperandProperties(local, arch, spec.inputBits, spec.legacy, true, false, "scalar precision conversion")
	form.rounding, form.sae = controls.rounding, controls.sae
	if err != nil {
		return form, true, err
	}
	if form.memory >= 0 {
		if controls.sae || controls.rounding != "" {
			return form, true, fmt.Errorf("%s %s embedded control requires a register source", arch, op)
		}
		if contextual {
			return form, true, x86VectorValueMemoryContext(ins)
		}
		if err := x86NamedMultiplyMemoryError(ins.Args[0], arch); err != nil {
			return form, true, err
		}
	}
	if err := x86Mode32VectorRegisterContext(ins, arch); err != nil {
		return form, true, err
	}
	if ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride {
		return form, true, fmt.Errorf("%w: %s needs its original default address mode", ErrProbeNeedsContext, op)
	}
	return form, true, nil
}

func x86TypedScalarPrecisionByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86ScalarPrecisionProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	effect := x86TypedByteEffect{requiresResultProof: true}
	for index, operand := range ins.Args {
		width := int64(16)
		if index == 0 {
			width = int64(form.spec.inputBits / 8)
		} else if index == form.mask {
			width = 8
		}
		effect.operands = append(effect.operands, x86TypedByteOperand{
			index: index, operand: operand, width: width,
			read:  index != form.destination || form.spec.legacy || form.mask >= 0 && !form.zeroing,
			write: index == form.destination,
		})
	}
	return effect, true, nil
}
