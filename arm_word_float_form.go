package plan9asm

import (
	"fmt"
	"strings"
)

type armConversionRegisterKind uint8

const (
	armConversionInvalid armConversionRegisterKind = iota
	armConversionFloat
	armConversionSingle
	armConversionCore
)

type armConversionRegister struct {
	kind   armConversionRegisterKind
	reg    Reg
	single int
}

type armWordFloatConversionForm struct {
	wordToFloat bool
	floatBits   int
	unsigned    bool
	source      armConversionRegister
	destination armConversionRegister
}

// Go's asm5 rows 84/85 are one native VCVT; rows 86/87 expand through
// FREGTMP (F15/S30). This effect belongs to the parsed operand form, not to
// the mnemonic alone. Raw S-register VCVT instructions have no such macro.
func (form armWordFloatConversionForm) usesScratch() bool {
	return form.source.kind == armConversionCore || form.destination.kind == armConversionCore
}

func parseARMWordFloatConversion(op string, ins Instr) (armWordFloatConversionForm, bool, error) {
	form := armWordFloatConversionForm{}
	switch op {
	case "MOVWF", "MOVWD", "MOVFW", "MOVDW":
	default:
		return form, false, nil
	}
	unsigned, err := armWordFloatConversionUnsigned(ins)
	if err != nil {
		return form, true, err
	}
	if len(ins.Args) != 2 {
		return form, true, fmt.Errorf("arm %s expects exactly 2 operands: %q", op, ins.Raw)
	}
	form.wordToFloat = strings.HasPrefix(op, "MOVW")
	form.floatBits = 32
	if strings.Contains(op, "D") {
		form.floatBits = 64
	}
	form.unsigned = unsigned
	// Only decoder-produced raw VCVT spellings can name S0..S31. Go source
	// still requires F0..F15; sharing physical storage grants no source form.
	rawSingles := strings.Contains(ins.Raw, "decoded from WORD")
	register := func(operand Operand) armConversionRegister {
		if operand.Kind == OpReg {
			if isARMFReg(operand.Reg) {
				return armConversionRegister{kind: armConversionFloat, reg: operand.Reg}
			}
			if isARMGeneralReg(operand.Reg) {
				return armConversionRegister{kind: armConversionCore, reg: operand.Reg}
			}
		}
		if number, ok := armSingleOperandNumber(operand); rawSingles && ok {
			return armConversionRegister{kind: armConversionSingle, single: number}
		}
		return armConversionRegister{}
	}
	form.source, form.destination = register(ins.Args[0]), register(ins.Args[1])
	floatRegister := func(operand armConversionRegister) bool {
		return operand.kind == armConversionFloat || form.floatBits == 32 && operand.kind == armConversionSingle
	}
	wordRegister := func(operand armConversionRegister) bool {
		return operand.kind == armConversionFloat || operand.kind == armConversionSingle || operand.kind == armConversionCore
	}
	if form.wordToFloat {
		if !wordRegister(form.source) || !floatRegister(form.destination) {
			return form, true, fmt.Errorf("arm %s expects R/F word source and F destination: %q", op, ins.Raw)
		}
	} else if !floatRegister(form.source) || !wordRegister(form.destination) {
		return form, true, fmt.Errorf("arm %s expects F source and R/F word destination: %q", op, ins.Raw)
	}
	return form, true, nil
}
