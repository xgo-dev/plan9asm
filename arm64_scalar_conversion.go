package plan9asm

import (
	"fmt"
	"strings"
)

type arm64ScalarConversionSpec struct {
	floatBits, integerBits int
	toFloat, unsigned      bool
	simdInteger            bool
}

var arm64ScalarConversionSpecs = map[Op]arm64ScalarConversionSpec{
	"FCVTZSD": {64, 64, false, false, false}, "FCVTZSDW": {64, 32, false, false, false},
	"FCVTZSS": {32, 64, false, false, false}, "FCVTZSSW": {32, 32, false, false, false},
	"FCVTZUD": {64, 64, false, true, false}, "FCVTZUDW": {64, 32, false, true, false},
	"FCVTZUS": {32, 64, false, true, false}, "FCVTZUSW": {32, 32, false, true, false},
	"SCVTFD": {64, 64, true, false, false}, "SCVTFS": {32, 64, true, false, false},
	"SCVTFWD": {64, 32, true, false, false}, "SCVTFWS": {32, 32, true, false, false},
	"UCVTFD": {64, 64, true, true, false}, "UCVTFS": {32, 64, true, true, false},
	"UCVTFWD": {64, 32, true, true, false}, "UCVTFWS": {32, 32, true, true, false},
	// These existing decoder spellings describe scalar SIMD integer carriers,
	// not the GP operand classes of Go asm7 case 29.
	"SCVTFDD": {64, 64, true, false, true}, "SCVTFSS": {32, 32, true, false, true},
	"UCVTFDD": {64, 64, true, true, true}, "UCVTFSS": {32, 32, true, true, true},
}

type arm64ScalarConversionForm struct {
	arm64ScalarConversionSpec
	source, destination Reg
	rounding            arm64FloatToIntegerRounding
}

func parseARM64ScalarConversion(op Op, instruction Instr) (arm64ScalarConversionForm, bool, error) {
	spec, matched := arm64ScalarConversionSpecs[op]
	if !matched {
		return arm64ScalarConversionForm{}, false, nil
	}
	if spec.simdInteger && !instruction.arm64Encoded {
		return arm64ScalarConversionForm{}, true, fmt.Errorf("arm64 %s is a decoder-only scalar conversion, not a Go source opcode: %q", op, instruction.Raw)
	}
	if strings.ToUpper(string(instruction.Op)) != string(op) || len(instruction.Args) != 2 ||
		instruction.Args[0].Kind != OpReg || instruction.Args[1].Kind != OpReg {
		return arm64ScalarConversionForm{}, true, fmt.Errorf("arm64 %s expects two scalar registers and no suffix: %q", op, instruction.Raw)
	}
	source, destination := instruction.Args[0].Reg, instruction.Args[1].Reg
	sourceOK, destinationOK := isARM64FReg(source), isARM64GeneralOrZeroReg(destination)
	if spec.toFloat {
		sourceOK, destinationOK = isARM64GeneralOrZeroReg(source), isARM64FReg(destination)
		if spec.simdInteger {
			sourceOK = isARM64FReg(source)
		}
	}
	if !sourceOK || !destinationOK {
		return arm64ScalarConversionForm{}, true, fmt.Errorf("arm64 %s has the wrong scalar register classes: %q", op, instruction.Raw)
	}
	return arm64ScalarConversionForm{spec, source, destination, arm64FloatRoundZero}, true, nil
}

// Only the written scalar bits become newly defined. FEAT_AFP permits the
// native instruction to preserve old destination bits when FPCR.NEP is set.
// Without a source-bound NEP=0 proof, virtual zero-filled slots do not define
// those bits. This is the existing lane-write rule, not a new caller grant.
func (c *arm64Ctx) recordARM64ScalarConversion(form arm64ScalarConversionForm) func() {
	flow := c.machineAvailability
	if flow == nil || flow.flagsOnly || flow.suspended != 0 {
		return func() {}
	}
	sourceBits, resultBits := form.floatBits, form.integerBits
	if form.toFloat {
		sourceBits, resultBits = form.integerBits, form.floatBits
	}
	c.recordMachineRegister(form.source, sourceBits, false)
	if form.toFloat || form.simdInteger {
		flow.blocks[flow.current].effects = append(flow.blocks[flow.current].effects, arm64MachineEffect{
			register: arm64MachineRegister(form.destination), width: resultBits,
			write: true, vectorSpan: true, source: flow.source,
		})
	} else {
		c.recordMachineRegister(form.destination, 64, true) // W writes zero the X upper half.
	}
	flow.suspended++
	return func() { flow.suspended-- }
}

func arm64ScalarConversionModifier(bits int, gp bool) string {
	if gp {
		if bits == 32 {
			return "w"
		}
		return "x"
	}
	switch bits {
	case 16:
		return "h"
	case 32:
		return "s"
	default:
		return "d"
	}
}

func (c *arm64Ctx) lowerARM64ScalarConversion(form arm64ScalarConversionForm) error {
	if _, _, valid := arm64ScalarFloatType(form.floatBits); !valid ||
		form.integerBits != 32 && form.integerBits != 64 && !(form.simdInteger && form.integerBits == 16) {
		return fmt.Errorf("arm64 invalid scalar conversion widths: %+v", form)
	}
	opcode := "scvtf"
	if form.toFloat {
		if form.unsigned {
			opcode = "ucvtf"
		}
	} else {
		modes := [...]string{"n", "a", "p", "m", "z"}
		if int(form.rounding) >= len(modes) {
			return fmt.Errorf("arm64 unsupported scalar float rounding mode %d", form.rounding)
		}
		opcode = "fcvt" + modes[form.rounding] + "s"
		if form.unsigned {
			opcode = "fcvt" + modes[form.rounding] + "u"
		}
	}
	finish := c.recordARM64ScalarConversion(form)
	defer finish()
	sourceBits, resultBits := form.floatBits, form.integerBits
	sourceGP, resultGP := false, !form.simdInteger
	if form.toFloat {
		sourceBits, resultBits = form.integerBits, form.floatBits
		sourceGP, resultGP = !form.simdInteger, false
	}
	sourceType, sourceConstraint := "<16 x i8>", "w"
	var source string
	var err error
	if sourceGP {
		sourceType, sourceConstraint = fmt.Sprintf("i%d", sourceBits), "r"
		source, err = c.loadRegisterWidth(form.source, sourceBits)
		if err == nil && sourceBits == 32 {
			narrow := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", narrow, source)
			source = "%" + narrow
		}
	} else {
		source, err = c.loadVReg(form.source)
	}
	if err != nil {
		return err
	}
	operation := fmt.Sprintf("%s ${0:%s}, ${1:%s}", opcode,
		arm64ScalarConversionModifier(resultBits, resultGP), arm64ScalarConversionModifier(sourceBits, sourceGP))
	result := c.newTmp()
	if resultGP {
		resultType := fmt.Sprintf("i%d", resultBits)
		// Native status is observable even with a ZR/dead result. The compiler
		// barrier orders this exact operation with existing native MRS/MSR.
		c.emitMachineNeutralNativeIR("  %%%s = call %s asm sideeffect %q, %q(%s %s)\n",
			result, resultType, operation, "=r,"+sourceConstraint+",~{memory}", sourceType, source)
		value := "%" + result
		if resultBits == 32 {
			wide := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", wide, value)
			value = "%" + wide
		}
		return c.storeReg(form.destination, value)
	}
	old, err := c.loadVReg(form.destination)
	if err != nil {
		return err
	}
	// Arm DDI0602's GP->F and scalar SIMD integer conversions merge V[d],
	// not V[n], under IsMerging(FPCR). A tied complete 128-bit operand lets
	// native hardware implement both zeroing and merging without fake FPCR.
	c.emitMachineNeutralNativeIR("  %%%s = call <16 x i8> asm sideeffect %q, %q(%s %s, <16 x i8> %s)\n",
		result, operation, "=w,"+sourceConstraint+",0,~{memory}", sourceType, source, old)
	return c.storeVReg(form.destination, "%"+result)
}
