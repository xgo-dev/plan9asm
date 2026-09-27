package plan9asm

import "fmt"

// decodedX86RORXInstruction recognizes the complete BMI2 RORXL/RORXQ Yml,
// Yrl, imm8 family, including register and every source-layout-safe ModRM/SIB
// memory form. x/arch v0.14 reports the VEX.0F3A encoding as an unknown AVX
// opcode, so it must be recovered before generic decoding.
func decodedX86RORXInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
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
	if len(code) < i+4 || code[i] != 0xc4 || code[i+1]&0x1f != 3 || code[i+3] != 0xf0 {
		return Instr{}, 0, false, nil
	}
	ok = true
	if mode != 32 && mode != 64 {
		return Instr{}, 0, true, fmt.Errorf("unsupported x86 mode %d", mode)
	}
	vexExt, vexByte := code[i+1], code[i+2]
	if vexByte&3 != 3 || vexByte&4 != 0 || vexByte&0x78 != 0x78 {
		return Instr{}, 0, true, fmt.Errorf("reserved RORX VEX prefix")
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
	modRM := code[i+4]
	destinationNumber := int(modRM>>3&7) + rExt*8
	if mode == 32 && destinationNumber >= 8 {
		return Instr{}, 0, true, fmt.Errorf("extended destination register in 32-bit mode")
	}
	destination, valid := decodedX86GeneralRegister(destinationNumber)
	if !valid {
		return Instr{}, 0, true, fmt.Errorf("invalid destination register %d", destinationNumber)
	}
	source, consumed, err := decodedX86VEXRMSource(code[i+4:], mode, bExt, xExt, segment)
	if err != nil {
		return Instr{}, 0, true, err
	}
	if len(code) <= i+4+consumed {
		return Instr{}, 0, true, fmt.Errorf("missing imm8")
	}
	immediate := int64(code[i+4+consumed])
	op := Op("RORXL")
	if width64 && mode == 64 {
		op = "RORXQ"
	}
	instruction = Instr{
		Op: op,
		Args: []Operand{
			{Kind: OpImm, Imm: immediate},
			source,
			{Kind: OpReg, Reg: destination},
		},
		Raw: fmt.Sprintf("%s $%d, %s, %s", op, immediate, source.String(), destination),
	}
	return instruction, i + 5 + consumed, true, nil
}
