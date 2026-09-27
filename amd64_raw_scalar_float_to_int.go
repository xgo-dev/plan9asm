package plan9asm

import "fmt"

// Decode the complete Go 1.27 scalar floating-point-to-GP family. Signed
// forms have VEX and EVEX encodings; unsigned forms are EVEX-only. The named
// lowerer and this decoder share amd64ScalarFloatToIntSpecs so W, F2/F3,
// truncation, and signedness cannot drift between the two entry points.
func decodedX86ScalarFloatToIntegerInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.mapNumber != 1 || (p.pp != 2 && p.pp != 3) {
		return Instr{}, 0, false, nil
	}
	if p.opcode != 0x2c && p.opcode != 0x2d && p.opcode != 0x78 && p.opcode != 0x79 {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("scalar float-to-integer: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	unsigned := p.opcode == 0x78 || p.opcode == 0x79
	truncating := p.opcode == 0x2c || p.opcode == 0x78
	if unsigned && !p.evex {
		return fail("unsigned conversion requires EVEX")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if p.upper != 0 {
		return fail("reserved vvvv/V' field")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if mode == 32 && (p.w || p.r != 0 || p.b != 0 || p.x != 0) {
		return fail("64-bit or extended register encoding in 32-bit mode")
	}
	if p.evex {
		if !p.fixed || p.mask != 0 || p.zero || p.r >= 2 {
			return fail("invalid EVEX fixed, mask, zeroing or GP extension field")
		}
		if p.broadcast && code[p.modRM]>>6 != 3 {
			return fail("SAE or embedded rounding requires register source")
		}
		if !p.broadcast && p.vectorLength != 0 {
			return fail("scalar conversion without rounding requires EVEX.128")
		}
	} else if p.vectorLength != 0 {
		return fail("scalar conversion requires VEX.128")
	}

	inputBits := 32
	if p.pp == 3 {
		inputBits = 64
	}
	outputBits := 32
	if p.w {
		outputBits = 64
	}
	var op Op
	for name, spec := range amd64ScalarFloatToIntSpecs {
		if spec.vector && spec.inputBits == inputBits && spec.outputBits == outputBits &&
			spec.truncating == truncating && spec.unsigned == unsigned {
			op = name
			break
		}
	}
	if op == "" {
		return fail("encoding has no Go scalar conversion form")
	}
	if p.evex && p.broadcast {
		if truncating {
			op += ".SAE"
		} else {
			op += [...]Op{".RN_SAE", ".RD_SAE", ".RU_SAE", ".RZ_SAE"}[p.vectorLength]
		}
	}
	var source Operand
	var consumed int
	var err error
	if p.evex {
		source, consumed, err = decodedX86EVEXRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, "X", inputBits/8)
	} else {
		source, consumed, err = decodedX86VEXVectorRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, "X")
	}
	if err != nil {
		return Instr{}, 0, true, err
	}
	destinationNumber := int(code[p.modRM]>>3&7) + (p.r&1)*8
	destinationReg, valid := decodedX86GeneralRegister(destinationNumber)
	if !valid {
		return fail("invalid GP destination")
	}
	destination := Operand{Kind: OpReg, Reg: destinationReg}
	return Instr{
		Op:   op,
		Args: []Operand{source, destination},
		Raw:  fmt.Sprintf("%s %s, %s", op, source.String(), destination.String()),
	}, p.modRM + consumed, true, nil
}
