package plan9asm

import (
	"fmt"
	"strings"
)

type x86RawScalarHalfConversionForm struct {
	op                    Op
	mapNumber, pp, opcode int
	w                     bool
}

var x86RawScalarHalfConversionForms = [...]x86RawScalarHalfConversionForm{
	{"VCVTSH2SS", 6, 0, 0x13, false},
	{"VCVTSS2SH", 5, 0, 0x1d, false},
	{"VCVTSH2SD", 5, 2, 0x5a, false},
	{"VCVTSD2SH", 5, 3, 0x5a, true},
}

func x86RawScalarHalfConversionFormFor(p x86RawVectorEncoding) (x86RawScalarHalfConversionForm, bool) {
	if p.evex {
		for _, form := range x86RawScalarHalfConversionForms {
			if p.mapNumber == form.mapNumber && p.pp == form.pp && p.opcode == form.opcode {
				return form, true
			}
		}
	}
	return x86RawScalarHalfConversionForm{}, false
}

func decodedX86ScalarHalfConversionInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, recognized := decodeX86RawVectorEncoding(code)
	form, matched := x86RawScalarHalfConversionFormFor(p)
	if !recognized || !matched {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("scalar half conversion: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if !p.fixed || p.w != form.w || p.zero && p.mask == 0 {
		return fail("invalid EVEX fixed, width or zeroing field")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if p.broadcast && code[p.modRM]>>6 != 3 {
		return fail("scalar conversion does not support memory broadcast")
	}
	if mode == 32 && (p.r != 0 || p.b != 0 || p.x != 0 || p.upper >= 8) {
		return fail("extended register or address in 32-bit mode")
	}
	spec := amd64HalfConversionSpecs[string(form.op)]
	source, consumed, err := decodedX86EVEXRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, "X", spec.inputBits/8)
	if err != nil {
		return Instr{}, 0, true, err
	}
	op := form.op
	if p.broadcast {
		if spec.inputBits == 16 {
			op += ".SAE"
		} else {
			op += [...]Op{".RN_SAE", ".RD_SAE", ".RU_SAE", ".RZ_SAE"}[p.vectorLength]
		}
	}
	if p.zero {
		op += ".Z"
	}
	args := []Operand{source, {Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", p.upper))}}
	if p.mask != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", p.mask))})
	}
	destination := int(code[p.modRM]>>3&7) + p.r*8
	args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", destination))})
	printed := make([]string, len(args))
	for index, arg := range args {
		printed[index] = arg.String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(printed, ", ")), x86Encoded: true}, p.modRM + consumed, true, nil
}

func decodeX86RawScalarHalfConversionRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, recognized := decodeX86RawVectorEncoding(code[offset:])
	form, matched := x86RawScalarHalfConversionFormFor(p)
	if !recognized || !matched || p.segment != "" || p.addressOverride {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRM := offset + p.modRM
	if len(code) <= modRM || code[modRM]&0xc7 != 5 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	width := amd64HalfConversionSpecs[string(form.op)].inputBits / 8
	return x86RawRIPDataThroughDecoder(code, offset, mode, modRM, width, decodedX86ScalarHalfConversionInstruction, "scalar half conversion")
}
