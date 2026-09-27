package plan9asm

import (
	"fmt"
	"strings"
)

// Go 1.27's packed-multiply rows share _yvandnpd's operand grammar. The
// opcode/map selects the lane operation; W selects Q only for opcode 40/0F38.
// The word operations have no broadcast row, whereas D/Q permit it.
type x86PackedMultiplyForm struct {
	mapID         byte
	opcode        byte
	vexOp         Op
	evexW0Op      Op
	evexW1Op      Op
	broadcastByte int
}

var x86PackedMultiplyForms = [...]x86PackedMultiplyForm{
	{mapID: 1, opcode: 0xd5, vexOp: "VPMULLW", evexW0Op: "VPMULLW", evexW1Op: "VPMULLW"},
	{mapID: 1, opcode: 0xe5, vexOp: "VPMULHW", evexW0Op: "VPMULHW", evexW1Op: "VPMULHW"},
	{mapID: 1, opcode: 0xe4, vexOp: "VPMULHUW", evexW0Op: "VPMULHUW", evexW1Op: "VPMULHUW"},
	{mapID: 2, opcode: 0x0b, vexOp: "VPMULHRSW", evexW0Op: "VPMULHRSW", evexW1Op: "VPMULHRSW"},
	{mapID: 2, opcode: 0x40, vexOp: "VPMULLD", evexW0Op: "VPMULLD", evexW1Op: "VPMULLQ", broadcastByte: 4},
}

func x86PackedMultiplyFormFor(mapID, opcode byte) (x86PackedMultiplyForm, bool) {
	for _, form := range x86PackedMultiplyForms {
		if form.mapID == mapID && form.opcode == opcode {
			return form, true
		}
	}
	return x86PackedMultiplyForm{}, false
}

// Keep the direct decoder used by the exhaustive VPMULLD/Q tests separate
// from the dispatcher, while sharing its parser with the word-multiply rows.
func decodedX86PackedMultiplyLowInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	instruction, length, ok, err = decodedX86PackedMultiplyInstruction(code, mode)
	if !ok || err != nil || instruction.Op == "VPMULLD" || strings.HasPrefix(string(instruction.Op), "VPMULLD.") ||
		instruction.Op == "VPMULLQ" || strings.HasPrefix(string(instruction.Op), "VPMULLQ.") {
		return instruction, length, ok, err
	}
	return Instr{}, 0, false, nil
}

func decodedX86PackedMultiplyInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	p, recognized := decodeX86RawVectorEncoding(code)
	if !recognized {
		return Instr{}, 0, false, nil
	}
	if p.evex {
		return decodedX86EVEXPackedMultiplyInstruction(
			code, p.modRM-5, mode, p.segment, p.addressOverride,
		)
	}
	if p.pp != 1 {
		return Instr{}, 0, false, nil
	}
	form, recognized := x86PackedMultiplyFormFor(byte(p.mapNumber), byte(p.opcode))
	if !recognized || p.w && form.opcode == 0x40 {
		return Instr{}, 0, false, nil
	}
	ok = true
	if p.addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	modRMIndex := p.modRM
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	vectorName := "X"
	if p.vectorLength != 0 {
		vectorName = "Y"
	}
	secondSourceNumber := p.upper
	destinationNumber := int(code[modRMIndex]>>3&7) + p.r*8
	if mode == 32 && (secondSourceNumber >= 8 || destinationNumber >= 8 ||
		code[modRMIndex]>>6 == 3 && int(code[modRMIndex]&7)+p.b*8 >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended vector register in 32-bit mode")
	}
	firstSource, consumed, decodeErr := decodedX86VEXVectorRMOperand(
		code[modRMIndex:], mode, p.b, p.x, p.segment, vectorName,
	)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	secondSource := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, secondSourceNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, destinationNumber))}
	instruction = Instr{
		Op:   form.vexOp,
		Args: []Operand{firstSource, secondSource, destination},
		Raw:  fmt.Sprintf("%s %s, %s, %s", form.vexOp, firstSource.String(), secondSource.String(), destination.String()),
	}
	return instruction, modRMIndex + consumed, true, nil
}

func decodedX86EVEXPackedMultiplyInstruction(code []byte, i, mode int, segment Reg, addressOverride bool) (instruction Instr, length int, ok bool, err error) {
	if len(code) < i+5 {
		return Instr{}, 0, false, nil
	}
	p0, p1, p2 := code[i+1], code[i+2], code[i+3]
	if p1&0x07 != 5 {
		return Instr{}, 0, false, nil
	}
	form, recognized := x86PackedMultiplyFormFor(p0&0x0f, code[i+4])
	if !recognized {
		return Instr{}, 0, false, nil
	}
	ok = true
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	vectorBits := (p2 >> 5) & 3
	if vectorBits == 3 {
		return Instr{}, 0, true, fmt.Errorf("reserved EVEX vector length")
	}
	vectorName := [...]string{"X", "Y", "Z"}[vectorBits]
	vectorWidth := [...]int{16, 32, 64}[vectorBits]
	width64 := p1&0x80 != 0
	op := form.evexW0Op
	if width64 {
		op = form.evexW1Op
	}
	laneBytes := form.broadcastByte
	if width64 && laneBytes != 0 {
		laneBytes = 8
	}
	maskNumber := int(p2 & 7)
	zeroing := p2&0x80 != 0
	if zeroing && maskNumber == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing requires a nonzero mask")
	}
	if mode == 32 && maskNumber != 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX masking is unavailable for 386 packed multiply forms")
	}

	rExt := int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	xExt := int(^p0>>6) & 1
	bExt := int(^p0>>5) & 1
	modRMIndex := i + 5
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	modRM := code[modRMIndex]
	broadcast := p2&0x10 != 0
	if broadcast && laneBytes == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX broadcast is not available for %s", op)
	}
	if broadcast && modRM>>6 == 3 {
		return Instr{}, 0, true, fmt.Errorf("EVEX broadcast requires a memory source")
	}
	secondSourceNumber := (int(^p1>>3) & 15) + (int(^p2>>3)&1)*16
	destinationNumber := int(modRM>>3&7) + rExt*8 + rHighExt*16
	firstSourceNumber := int(modRM&7) + bExt*8 + xExt*16
	if mode == 32 && vectorName == "Z" && (secondSourceNumber >= 8 || destinationNumber >= 8 || modRM>>6 == 3 && firstSourceNumber >= 8) {
		return Instr{}, 0, true, fmt.Errorf("high Z register is unavailable in 32-bit mode")
	}
	disp8Scale := vectorWidth
	if broadcast {
		disp8Scale = laneBytes
	}
	firstSource, consumed, decodeErr := decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorName, disp8Scale)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	secondSource := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, secondSourceNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, destinationNumber))}
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
