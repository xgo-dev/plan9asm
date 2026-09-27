package plan9asm

import (
	"fmt"
	"strings"
)

// x86RawQQToFloatForm maps opcode and mandatory prefix to the Go 1.27
// QWORD-to-PS/PD optabs. PS narrows the Y/Z destination by one vector width.
func x86RawQQToFloatForm(p x86RawVectorEncoding) (base Op, narrow bool, ok bool) {
	switch {
	case p.opcode == 0x5b && p.pp == 0:
		return "VCVTQQ2PS", true, true
	case p.opcode == 0x7a && p.pp == 3:
		return "VCVTUQQ2PS", true, true
	case p.opcode == 0xe6 && p.pp == 2:
		return "VCVTQQ2PD", false, true
	case p.opcode == 0x7a && p.pp == 2:
		return "VCVTUQQ2PD", false, true
	default:
		return "", false, false
	}
}

// decodedX86RawQQToFloatInstruction handles all four EVEX QWORD-to-PS/PD
// conversion families, including every X/Y/Z, K-mask, broadcast, and
// maximum-width embedded-rounding form.
func decodedX86RawQQToFloatInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || !p.evex || !p.w || p.mapNumber != 1 {
		return Instr{}, 0, false, nil
	}
	base, narrow, recognized := x86RawQQToFloatForm(p)
	if !recognized {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("QWORD-to-float conversion: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if !p.fixed || p.addressOverride || p.upper != 0 {
		return fail("invalid EVEX fixed bit, address override, or reserved vvvv")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if p.zero && p.mask == 0 {
		return fail("zeroing requires a nonzero mask")
	}

	modRM := code[p.modRM]
	registerSource := modRM>>6 == 3
	rounding := p.broadcast && registerSource
	broadcast := p.broadcast && !registerSource
	if !rounding && p.vectorLength == 3 {
		return fail("reserved EVEX vector length")
	}

	sourceWidth := p.vectorLength
	if rounding {
		sourceWidth = 2
	}
	sourcePrefix := [...]string{"X", "Y", "Z"}[sourceWidth]
	destinationPrefix := sourcePrefix
	if narrow {
		destinationPrefix = [...]string{"X", "X", "Y"}[sourceWidth]
	}
	destinationNumber := int(modRM>>3&7) + p.r*8
	if mode == 32 && (p.mask != 0 || destinationNumber >= 8 ||
		registerSource && int(modRM&7)+p.b*8+p.x*16 >= 8) {
		return fail("extended vector register or mask in 32-bit mode")
	}
	disp8Scale := 16 << sourceWidth
	if broadcast {
		disp8Scale = 8
	}
	source, consumed, err := decodedX86EVEXRMOperand(
		code[p.modRM:], mode, p.b, p.x, p.segment, sourcePrefix, disp8Scale,
	)
	if err != nil {
		return Instr{}, 0, true, err
	}

	op := base
	if narrow && !rounding {
		op += [...]Op{"X", "Y", ""}[sourceWidth]
	}
	if broadcast {
		op += ".BCST"
	}
	if rounding {
		op += [...]Op{".RN_SAE", ".RD_SAE", ".RU_SAE", ".RZ_SAE"}[p.vectorLength]
	}
	if p.zero {
		op += ".Z"
	}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", destinationPrefix, destinationNumber))}
	args := []Operand{source}
	if p.mask != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", p.mask))})
	}
	args = append(args, destination)
	printed := make([]string, len(args))
	for index := range args {
		printed[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(printed, ", "))}, p.modRM + consumed, true, nil
}
