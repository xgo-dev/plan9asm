package plan9asm

import (
	"fmt"
	"strings"
)

type x86FloatArithmeticFamily string

const (
	x86FloatAddSubtract    x86FloatArithmeticFamily = "add/sub"
	x86FloatMultiplyDivide x86FloatArithmeticFamily = "mul/div"
	x86FloatMinimumMaximum x86FloatArithmeticFamily = "min/max"
)

type x86FloatArithmeticSpec struct {
	bits           int
	legacy, scalar bool
	mode           amd64BinaryFloatingMode
}

// These are the complete six yxm/VEX/EVEX arithmetic pairs. Operand shapes
// share one grammar; operation tags retain distinct arithmetic and FP effects.
var x86FloatArithmeticSpecs = map[Op]x86FloatArithmeticSpec{
	"ADDPS": {32, true, false, amd64BinaryFloatingAdd}, "ADDPD": {64, true, false, amd64BinaryFloatingAdd},
	"ADDSS": {32, true, true, amd64BinaryFloatingAdd}, "ADDSD": {64, true, true, amd64BinaryFloatingAdd},
	"SUBPS": {32, true, false, amd64BinaryFloatingSub}, "SUBPD": {64, true, false, amd64BinaryFloatingSub},
	"SUBSS": {32, true, true, amd64BinaryFloatingSub}, "SUBSD": {64, true, true, amd64BinaryFloatingSub},
	"VADDPS": {32, false, false, amd64BinaryFloatingAdd}, "VADDPD": {64, false, false, amd64BinaryFloatingAdd},
	"VADDSS": {32, false, true, amd64BinaryFloatingAdd}, "VADDSD": {64, false, true, amd64BinaryFloatingAdd},
	"VSUBPS": {32, false, false, amd64BinaryFloatingSub}, "VSUBPD": {64, false, false, amd64BinaryFloatingSub},
	"VSUBSS": {32, false, true, amd64BinaryFloatingSub}, "VSUBSD": {64, false, true, amd64BinaryFloatingSub},
	"MULPS": {32, true, false, amd64BinaryFloatingMul}, "MULPD": {64, true, false, amd64BinaryFloatingMul},
	"MULSS": {32, true, true, amd64BinaryFloatingMul}, "MULSD": {64, true, true, amd64BinaryFloatingMul},
	"DIVPS": {32, true, false, amd64BinaryFloatingDiv}, "DIVPD": {64, true, false, amd64BinaryFloatingDiv},
	"DIVSS": {32, true, true, amd64BinaryFloatingDiv}, "DIVSD": {64, true, true, amd64BinaryFloatingDiv},
	"VMULPS": {32, false, false, amd64BinaryFloatingMul}, "VMULPD": {64, false, false, amd64BinaryFloatingMul},
	"VMULSS": {32, false, true, amd64BinaryFloatingMul}, "VMULSD": {64, false, true, amd64BinaryFloatingMul},
	"VDIVPS": {32, false, false, amd64BinaryFloatingDiv}, "VDIVPD": {64, false, false, amd64BinaryFloatingDiv},
	"VDIVSS": {32, false, true, amd64BinaryFloatingDiv}, "VDIVSD": {64, false, true, amd64BinaryFloatingDiv},
	"MINPS": {32, true, false, amd64BinaryFloatingMin}, "MINPD": {64, true, false, amd64BinaryFloatingMin},
	"MINSS": {32, true, true, amd64BinaryFloatingMin}, "MINSD": {64, true, true, amd64BinaryFloatingMin},
	"MAXPS": {32, true, false, amd64BinaryFloatingMax}, "MAXPD": {64, true, false, amd64BinaryFloatingMax},
	"MAXSS": {32, true, true, amd64BinaryFloatingMax}, "MAXSD": {64, true, true, amd64BinaryFloatingMax},
	"VMINPS": {32, false, false, amd64BinaryFloatingMin}, "VMINPD": {64, false, false, amd64BinaryFloatingMin},
	"VMINSS": {32, false, true, amd64BinaryFloatingMin}, "VMINSD": {64, false, true, amd64BinaryFloatingMin},
	"VMAXPS": {32, false, false, amd64BinaryFloatingMax}, "VMAXPD": {64, false, false, amd64BinaryFloatingMax},
	"VMAXSS": {32, false, true, amd64BinaryFloatingMax}, "VMAXSD": {64, false, true, amd64BinaryFloatingMax},
}

func (spec x86FloatArithmeticSpec) family() x86FloatArithmeticFamily {
	switch spec.mode {
	case amd64BinaryFloatingAdd, amd64BinaryFloatingSub:
		return x86FloatAddSubtract
	case amd64BinaryFloatingMul, amd64BinaryFloatingDiv:
		return x86FloatMultiplyDivide
	case amd64BinaryFloatingMin, amd64BinaryFloatingMax:
		return x86FloatMinimumMaximum
	}
	panic("non-arithmetic floating operation in arithmetic catalog")
}

type x86FloatArithmeticForm struct {
	x86FloatBinaryForm
	spec x86FloatArithmeticSpec
}

func x86FloatArithmeticProperties(ins Instr, arch string, family x86FloatArithmeticFamily) (x86FloatArithmeticForm, bool, error) {
	base, suffix, dotted := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	spec, known := x86FloatArithmeticSpecs[Op(base)]
	if !known || family != "" && spec.family() != family {
		return x86FloatArithmeticForm{}, false, nil
	}
	family = spec.family()
	form := x86FloatArithmeticForm{spec: spec}
	shape := ins
	literal := false
	sae := false
	if family == x86FloatMinimumMaximum {
		controls, valid := parseAMD64BinaryFloatingSuffix(suffix)
		sae, form.sae = controls.sae, controls.sae
		if !valid || dotted && suffix == "" || controls.rounding != "" || spec.legacy && dotted {
			return form, true, fmt.Errorf("%s %s has invalid MIN/MAX operands or controls: %q", arch, ins.Op, ins.Raw)
		}
		// Strip only the independently validated SAE control from this local
		// shape. Original operands/opcode remain the source and emitter input.
		if sae {
			shape.Op = Op(base)
			if controls.zeroing {
				shape.Op += ".Z"
			}
		}
	} else {
		literal = x86FloatArithmeticLiteral(ins, spec.legacy, spec.scalar)
	}
	var err error
	form.x86FloatBinaryForm, err = x86FloatBinaryOperandProperties(shape, arch, spec.bits, spec.legacy, spec.scalar, literal, string(family))
	form.sae = sae
	if err != nil {
		return form, true, err
	}
	if family == x86FloatMinimumMaximum {
		if sae && (ins.Args[0].Kind != OpReg || !spec.scalar && form.byteWidth != 64) {
			return form, true, fmt.Errorf("%s %s has invalid MIN/MAX operands or controls: %q", arch, ins.Op, ins.Raw)
		}
	}
	return form, true, x86Mode32VectorRegisterContext(ins, arch)
}

func (c *amd64Ctx) lowerFloatArithmetic(op Op, ins Instr, family x86FloatArithmeticFamily) (bool, bool, error) {
	local := ins
	local.Op = op
	form, known, err := x86FloatArithmeticProperties(local, c.goarch, family)
	if !known {
		return false, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		name := string(form.spec.family())
		if form.spec.family() == x86FloatMinimumMaximum {
			name = "MIN/MAX"
		}
		return true, false, fmt.Errorf("floating %s dispatch/source opcode mismatch: %s/%s", name, op, ins.Op)
	}
	if err != nil {
		return true, false, err
	}
	switch form.spec.family() {
	case x86FloatAddSubtract:
		return c.lowerFloatAddSubForm(local, form)
	case x86FloatMultiplyDivide:
		return c.lowerFloatMulDivForm(local, form)
	case x86FloatMinimumMaximum:
		return c.lowerFloatMinMaxForm(local, form)
	}
	panic("unregistered floating arithmetic family")
}
