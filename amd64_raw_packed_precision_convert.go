package plan9asm

import (
	"fmt"
	"strings"
)

// Opcode 5A with no prefix or 66 converts packed singles to doubles or
// doubles to singles. Go 1.27 exposes the VEX.128/.256 and EVEX.128/.256/.512
// forms under VCVTPS2PD and VCVTPD2PSX/Y (or unsuffixed Z). Scalar F2/F3 5A
// belongs to the separate scalar-precision grammar.
func decodedX86PackedPrecisionConvertInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.mapNumber != 1 || p.opcode != 0x5a || (p.pp != 0 && p.pp != 1) {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("packed precision conversion: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
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
	if p.evex {
		if !p.fixed || p.w != (p.pp == 1) || p.zero && p.mask == 0 {
			return fail("invalid EVEX fixed, width, mask or zeroing field")
		}
	}

	registerSource := code[p.modRM]>>6 == 3
	if mode == 32 {
		if !p.evex && (p.r != 0 || p.b != 0 || p.x != 0) {
			return fail("extended VEX register in 32-bit mode")
		}
		if p.evex && !registerSource && (p.b != 0 || p.x != 0) {
			return fail("extended memory address in 32-bit mode")
		}
	}
	embeddedControl := p.evex && p.broadcast && registerSource
	broadcast := p.evex && p.broadcast && !registerSource
	if p.evex && !embeddedControl && p.vectorLength > 2 {
		return fail("reserved EVEX vector length")
	}

	vectorLength := p.vectorLength
	if embeddedControl {
		vectorLength = 2 // SAE or rounding implies the 512-bit register form.
	}
	var op Op
	var sourcePrefix, destinationPrefix string
	var memoryScale int
	if p.pp == 0 {
		op = "VCVTPS2PD"
		destinationPrefix = [...]string{"X", "Y", "Z"}[vectorLength]
		sourcePrefix = "X"
		if vectorLength == 2 {
			sourcePrefix = "Y"
		}
		memoryScale = 8 << vectorLength
	} else {
		op = "VCVTPD2PS"
		if vectorLength < 2 {
			op += [...]Op{"X", "Y"}[vectorLength]
		}
		sourcePrefix = [...]string{"X", "Y", "Z"}[vectorLength]
		destinationPrefix = "X"
		if vectorLength == 2 {
			destinationPrefix = "Y"
		}
		memoryScale = 16 << vectorLength
	}
	if mode == 32 {
		if sourcePrefix == "Z" && registerSource && (p.b != 0 || p.x != 0) {
			return fail("Z8-Z31 are not Go assembler source registers in 32-bit mode")
		}
		if destinationPrefix == "Z" && p.r != 0 {
			return fail("Z8-Z31 are not Go assembler destination registers in 32-bit mode")
		}
	}
	if embeddedControl {
		if p.pp == 0 {
			op += ".SAE"
		} else {
			op += [...]Op{".RN_SAE", ".RD_SAE", ".RU_SAE", ".RZ_SAE"}[p.vectorLength]
		}
	} else if broadcast {
		op += ".BCST"
		if p.pp == 0 {
			memoryScale = 4
		} else {
			memoryScale = 8
		}
	}
	if p.zero {
		op += ".Z"
	}

	var source Operand
	var consumed int
	var err error
	if p.evex {
		source, consumed, err = decodedX86EVEXRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, sourcePrefix, memoryScale)
	} else {
		source, consumed, err = decodedX86VEXVectorRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, sourcePrefix)
	}
	if err != nil {
		return Instr{}, 0, true, err
	}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", destinationPrefix, int(code[p.modRM]>>3&7)+p.r*8))}
	args := []Operand{source}
	if p.mask != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", p.mask))})
	}
	args = append(args, destination)
	printed := make([]string, len(args))
	for i, arg := range args {
		printed[i] = arg.String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(printed, ", "))}, p.modRM + consumed, true, nil
}
