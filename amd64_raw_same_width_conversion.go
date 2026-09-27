package plan9asm

import (
	"fmt"
	"strings"
)

type decodedX86SameWidthConversionProperties struct {
	op        Op
	laneBytes int
	sae       bool
}

func decodedX86SameWidthConversionOpcode(opcode, pp byte) (decodedX86SameWidthConversionProperties, bool) {
	properties := map[[2]byte]decodedX86SameWidthConversionProperties{
		{0x5b, 0}: {op: "VCVTDQ2PS", laneBytes: 4},
		{0x5b, 1}: {op: "VCVTPS2DQ", laneBytes: 4},
		{0x5b, 2}: {op: "VCVTTPS2DQ", laneBytes: 4, sae: true},
		{0x51, 0}: {op: "VSQRTPS", laneBytes: 4},
		{0x51, 1}: {op: "VSQRTPD", laneBytes: 8},
	}[[2]byte{opcode, pp}]
	return properties, properties.op != ""
}

// decodedX86SameWidthConversionInstruction recognizes every VEX and EVEX
// encoding behind Go 1.27's _yvcvtdq2ps table: VCVTDQ2PS, VCVTPS2DQ,
// VCVTTPS2DQ, VSQRTPD, and VSQRTPS. It covers X/Y/Z registers, ModRM/SIB
// memory, masking, zeroing, broadcasts, embedded rounding, SAE, and compressed
// displacements before the generic decoder can consume an incorrect length.
func decodedX86SameWidthConversionInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
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
			goto vectorPrefix
		}
	}

vectorPrefix:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	if len(code) > i && code[i] == 0x62 {
		return decodedX86EVEXSameWidthConversionInstruction(code, i, mode, segment, addressOverride)
	}

	var vexLength, rExt, xExt, bExt int
	var vexBits, opcode byte
	switch {
	case len(code) >= i+4 && code[i] == 0xc5:
		vexLength = 2
		vexBits = code[i+1]
		rExt = int(^vexBits>>7) & 1
		opcode = code[i+2]
	case len(code) >= i+5 && code[i] == 0xc4 && code[i+1]&0x1f == 1:
		vexLength = 3
		vexBits = code[i+2]
		rExt = int(^code[i+1]>>7) & 1
		xExt = int(^code[i+1]>>6) & 1
		bExt = int(^code[i+1]>>5) & 1
		opcode = code[i+3]
	default:
		return Instr{}, 0, false, nil
	}
	properties, recognized := decodedX86SameWidthConversionOpcode(opcode, vexBits&3)
	if !recognized {
		return Instr{}, 0, false, nil
	}
	ok = true
	if vexLength == 3 && vexBits&0x80 != 0 {
		return Instr{}, 0, true, fmt.Errorf("VEX.W must be zero")
	}
	if vexBits&0x78 != 0x78 {
		return Instr{}, 0, true, fmt.Errorf("VEX.vvvv must be reserved")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}

	opcodeIndex := i + vexLength
	modRMIndex := opcodeIndex + 1
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	vectorPrefix := "X"
	if vexBits&0x04 != 0 {
		vectorPrefix = "Y"
	}
	modRM := code[modRMIndex]
	destinationNumber := int(modRM>>3&7) + rExt*8
	if mode == 32 && (destinationNumber >= 8 || modRM>>6 == 3 && int(modRM&7)+bExt*8 >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended vector register in 32-bit mode")
	}
	source, consumed, decodeErr := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorPrefix)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, destinationNumber))}
	instruction = Instr{
		Op:   properties.op,
		Args: []Operand{source, destination},
		Raw:  fmt.Sprintf("%s %s, %s", properties.op, source.String(), destination.String()),
	}
	return instruction, modRMIndex + consumed, true, nil
}

func decodedX86EVEXSameWidthConversionInstruction(code []byte, i, mode int, segment Reg, addressOverride bool) (instruction Instr, length int, ok bool, err error) {
	if len(code) < i+6 {
		return Instr{}, 0, false, nil
	}
	p0, p1, p2 := code[i+1], code[i+2], code[i+3]
	opcode := code[i+4]
	half := p0&0x0f == 5 && opcode == 0x51 && p1&3 == 0
	if p0&0x0f != 1 && !half {
		return Instr{}, 0, false, nil
	}
	properties, recognized := decodedX86SameWidthConversionOpcode(opcode, p1&3)
	if half {
		properties = decodedX86SameWidthConversionProperties{op: "VSQRTPH", laneBytes: 2}
	}
	if !recognized {
		return Instr{}, 0, false, nil
	}
	ok = true
	if p1&0x04 == 0 {
		return Instr{}, 0, true, fmt.Errorf("invalid EVEX prefix")
	}
	width64 := p1&0x80 != 0
	wantWidth64 := properties.laneBytes == 8
	if width64 != wantWidth64 {
		return Instr{}, 0, true, fmt.Errorf("EVEX.W does not match conversion element type")
	}
	if p1&0x78 != 0x78 || p2&0x08 == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX.vvvv must be reserved")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}

	modRMIndex := i + 5
	modRM := code[modRMIndex]
	vectorBits := (p2 >> 5) & 3
	evexB := p2&0x10 != 0
	registerSource := modRM>>6 == 3
	embeddedControl := evexB && registerSource
	broadcast := evexB && !registerSource
	if !embeddedControl && vectorBits == 3 {
		return Instr{}, 0, true, fmt.Errorf("reserved EVEX vector length")
	}

	vectorPrefix := "Z"
	vectorWidth := 64
	if !embeddedControl {
		vectorPrefix = [...]string{"X", "Y", "Z"}[vectorBits]
		vectorWidth = [...]int{16, 32, 64}[vectorBits]
	}
	disp8Scale := vectorWidth
	if broadcast {
		disp8Scale = properties.laneBytes
	}
	maskNumber := int(p2 & 7)
	zeroing := p2&0x80 != 0
	if zeroing && maskNumber == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing requires a nonzero mask")
	}

	rExt := int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	xExt := int(^p0>>6) & 1
	bExt := int(^p0>>5) & 1
	destinationNumber := int(modRM>>3&7) + rExt*8 + rHighExt*16
	if mode == 32 && (maskNumber != 0 && !half || destinationNumber >= 8 || modRM>>6 == 3 && int(modRM&7)+bExt*8+xExt*16 >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended vector register or mask in 32-bit mode")
	}
	source, consumed, decodeErr := decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorPrefix, disp8Scale)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}

	op := properties.op
	if broadcast {
		op += ".BCST"
	}
	if embeddedControl {
		if properties.sae {
			op += ".SAE"
		} else {
			op += [...]Op{".RN_SAE", ".RD_SAE", ".RU_SAE", ".RZ_SAE"}[vectorBits]
		}
	}
	if zeroing {
		op += ".Z"
	}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, destinationNumber))}
	args := []Operand{source}
	if maskNumber != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", maskNumber))})
	}
	args = append(args, destination)
	rawArgs := make([]string, len(args))
	for index := range args {
		rawArgs[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", ")), x86Encoded: half}, modRMIndex + consumed, true, nil
}
