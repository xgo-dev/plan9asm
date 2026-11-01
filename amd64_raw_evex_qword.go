package plan9asm

import (
	"fmt"
	"strings"
)

// These complete EVEX-only qword families share physical field decoding,
// not operand authority or their independent numerical and memory effects.
func decodedX86EVEXQwordBinaryInstruction(code []byte, mode int, lookup bool) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto evex
		}
	}

evex:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	if len(code) < i+6 || code[i] != 0x62 || code[i+1]&0x0f != 2 || code[i+2]&0x07 != 5 {
		return Instr{}, 0, false, nil
	}
	op := Op("")
	switch code[i+4] {
	case 0xb4:
		if lookup {
			return Instr{}, 0, false, nil
		}
		op = "VPMADD52LUQ"
	case 0xb5:
		if lookup {
			return Instr{}, 0, false, nil
		}
		op = "VPMADD52HUQ"
	case 0x83, 0x8f:
		if !lookup {
			return Instr{}, 0, false, nil
		}
		op = "VPMULTISHIFTQB"
		if code[i+4] == 0x8f {
			op = "VPSHUFBITQMB"
		}
	default:
		return Instr{}, 0, false, nil
	}
	ok = true
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	p0, p1, p2 := code[i+1], code[i+2], code[i+3]
	if (p1&0x80 != 0) != (op != "VPSHUFBITQMB") {
		return Instr{}, 0, true, fmt.Errorf("EVEX.W does not match %s", op)
	}
	vectorBits := (p2 >> 5) & 3
	if vectorBits == 3 {
		return Instr{}, 0, true, fmt.Errorf("reserved EVEX vector length")
	}
	vectorName := [...]string{"X", "Y", "Z"}[vectorBits]
	vectorWidth := [...]int{16, 32, 64}[vectorBits]
	maskNumber := int(p2 & 7)
	zeroing := p2&0x80 != 0
	if op == "VPSHUFBITQMB" && (zeroing || p2&0x10 != 0) {
		return Instr{}, 0, true, fmt.Errorf("mask-result lookup has no zeroing or broadcast encoding")
	}
	if zeroing && maskNumber == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing requires a nonzero mask")
	}
	rExt := int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	xExt := int(^p0>>6) & 1
	bExt := int(^p0>>5) & 1
	modRMIndex := i + 5
	modRM := code[modRMIndex]
	broadcast := p2&0x10 != 0
	if broadcast && modRM>>6 == 3 {
		return Instr{}, 0, true, fmt.Errorf("EVEX broadcast requires a memory source")
	}
	secondSourceNumber := (int(^p1>>3) & 15) + (int(^p2>>3)&1)*16
	destinationNumber := int(modRM>>3&7) + rExt*8 + rHighExt*16
	if op == "VPSHUFBITQMB" && destinationNumber >= 8 {
		return Instr{}, 0, true, fmt.Errorf("%w: unbound extended K destination field", ErrProbeNeedsContext)
	}
	if mode == 32 && (secondSourceNumber >= 8 || destinationNumber >= 8 || modRM>>6 == 3 && int(modRM&7)+bExt*8+xExt*16 >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended vector register in 32-bit mode")
	}
	disp8Scale := vectorWidth
	if broadcast {
		disp8Scale = 8
	}
	firstSource, consumed, decodeErr := decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorName, disp8Scale)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	secondSource := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, secondSourceNumber))}
	destinationName := vectorName
	if op == "VPSHUFBITQMB" {
		destinationName = "K"
	}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", destinationName, destinationNumber))}
	args := []Operand{firstSource, secondSource}
	if maskNumber != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", maskNumber))})
	}
	args = append(args, destination)
	if broadcast {
		op += ".BCST"
	}
	if zeroing {
		op += ".Z"
	}
	rawArgs := make([]string, len(args))
	for index := range args {
		rawArgs[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", "))}, modRMIndex + consumed, true, nil
}
