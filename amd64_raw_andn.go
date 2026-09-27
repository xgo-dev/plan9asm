package plan9asm

import "fmt"

// decodedX86ANDNInstruction recognizes the complete BMI1 ANDNL/ANDNQ
// Yml,Yrl,Yrl family. x/arch v0.14 reports this VEX.NDS encoding as an
// unknown AVX opcode, so recover every register and safe ModRM/SIB memory form
// before generic decoding.
func decodedX86ANDNInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
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
			goto vex
		}
	}

vex:
	if len(code) < i+4 || code[i] != 0xc4 || code[i+1]&0x1f != 2 || code[i+3] != 0xf2 {
		return Instr{}, 0, false, nil
	}
	ok = true
	if mode != 32 && mode != 64 {
		return Instr{}, 0, true, fmt.Errorf("unsupported x86 mode %d", mode)
	}
	vexExt, vexByte := code[i+1], code[i+2]
	if vexByte&7 != 0 {
		return Instr{}, 0, true, fmt.Errorf("reserved ANDN VEX prefix")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	if len(code) <= i+4 {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	rExt := int(^vexExt>>7) & 1
	xExt := int(^vexExt>>6) & 1
	bExt := int(^vexExt>>5) & 1
	width64 := vexByte&0x80 != 0
	secondNumber := int(^vexByte>>3) & 15
	modRM := code[i+4]
	destinationNumber := int(modRM>>3&7) + rExt*8
	if mode == 32 && (secondNumber >= 8 || destinationNumber >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended source or destination register in 32-bit mode")
	}
	second, valid := decodedX86GeneralRegister(secondNumber)
	if !valid {
		return Instr{}, 0, true, fmt.Errorf("invalid second-source register %d", secondNumber)
	}
	destination, valid := decodedX86GeneralRegister(destinationNumber)
	if !valid {
		return Instr{}, 0, true, fmt.Errorf("invalid destination register %d", destinationNumber)
	}
	first, consumed, err := decodedX86VEXRMSource(code[i+4:], mode, bExt, xExt, segment)
	if err != nil {
		return Instr{}, 0, true, err
	}
	op := Op("ANDNL")
	if width64 && mode == 64 {
		op = "ANDNQ"
	}
	instruction = Instr{
		Op:   op,
		Args: []Operand{first, {Kind: OpReg, Reg: second}, {Kind: OpReg, Reg: destination}},
		Raw:  fmt.Sprintf("%s %s, %s, %s", op, first.String(), second, destination),
	}
	return instruction, i + 4 + consumed, true, nil
}
