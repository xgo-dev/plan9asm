package plan9asm

import "fmt"

type decodedX86MaskVectorMoveProperties struct {
	op           Op
	maskToVector bool
}

func decodedX86MaskVectorMoveOpcode(opcode byte, width64 bool) (decodedX86MaskVectorMoveProperties, bool) {
	width := byte(0)
	if width64 {
		width = 1
	}
	properties := map[[2]byte]decodedX86MaskVectorMoveProperties{
		{0x28, 0}: {op: "VPMOVM2B", maskToVector: true},
		{0x28, 1}: {op: "VPMOVM2W", maskToVector: true},
		{0x38, 0}: {op: "VPMOVM2D", maskToVector: true},
		{0x38, 1}: {op: "VPMOVM2Q", maskToVector: true},
		{0x29, 0}: {op: "VPMOVB2M"},
		{0x29, 1}: {op: "VPMOVW2M"},
		{0x39, 0}: {op: "VPMOVD2M"},
		{0x39, 1}: {op: "VPMOVQ2M"},
	}[[2]byte{opcode, width}]
	return properties, properties.op != ""
}

// decodedX86MaskVectorMoveInstruction recognizes Go 1.27's complete
// VPMOVM2{B,W,D,Q} and VPMOV{B,W,D,Q}2M family. These EVEX-only instructions
// have register-only K/X/Y/Z forms and do not permit writemasking, zeroing, or
// EVEX.b. Recover all vector registers and widths before the generic decoder.
func decodedX86MaskVectorMoveInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64, 0x65:
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto evex
		}
	}

evex:
	if mode != 32 && mode != 64 || len(code) < i+6 || code[i] != 0x62 {
		return Instr{}, 0, false, nil
	}
	p0, p1, p2 := code[i+1], code[i+2], code[i+3]
	opcode := code[i+4]
	if p0&0x0f != 2 || p1&3 != 2 {
		return Instr{}, 0, false, nil
	}
	properties, recognized := decodedX86MaskVectorMoveOpcode(opcode, p1&0x80 != 0)
	if !recognized {
		return Instr{}, 0, false, nil
	}
	ok = true
	if p1&0x04 == 0 {
		return Instr{}, 0, true, fmt.Errorf("invalid EVEX prefix")
	}
	if p1&0x78 != 0x78 || p2&0x08 == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX.vvvv must be reserved")
	}
	if p2&0x97 != 0 {
		return Instr{}, 0, true, fmt.Errorf("mask/vector moves do not support masking, zeroing, or EVEX.b")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	vectorBits := (p2 >> 5) & 3
	if vectorBits == 3 {
		return Instr{}, 0, true, fmt.Errorf("reserved EVEX vector length")
	}

	modRMIndex := i + 5
	modRM := code[modRMIndex]
	if modRM>>6 != 3 {
		return Instr{}, 0, true, fmt.Errorf("mask/vector moves require register operands")
	}
	rExt := int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	xExt := int(^p0>>6) & 1
	bExt := int(^p0>>5) & 1
	vectorNumber := 0
	maskNumber := 0
	if properties.maskToVector {
		if xExt != 0 || bExt != 0 {
			return Instr{}, 0, true, fmt.Errorf("K source register cannot be extended")
		}
		vectorNumber = int(modRM>>3&7) + rExt*8 + rHighExt*16
		maskNumber = int(modRM & 7)
	} else {
		if rExt != 0 || rHighExt != 0 {
			return Instr{}, 0, true, fmt.Errorf("K destination register cannot be extended")
		}
		vectorNumber = int(modRM&7) + bExt*8 + xExt*16
		maskNumber = int(modRM >> 3 & 7)
	}
	if mode == 32 && vectorNumber >= 8 {
		return Instr{}, 0, true, fmt.Errorf("extended vector register in 32-bit mode")
	}
	vectorPrefix := [...]string{"X", "Y", "Z"}[vectorBits]
	vector := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, vectorNumber))}
	mask := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", maskNumber))}
	args := []Operand{vector, mask}
	if properties.maskToVector {
		args[0], args[1] = args[1], args[0]
	}
	return Instr{Op: properties.op, Args: args, Raw: fmt.Sprintf("%s %s, %s", properties.op, args[0].String(), args[1].String())}, modRMIndex + 1, true, nil
}
