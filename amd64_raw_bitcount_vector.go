package plan9asm

import (
	"fmt"
	"strings"
)

type x86RawVectorBitCountForm struct {
	op     Op
	opcode int
	w      bool
}

// The six Go 1.27 _yvexpandpd bit-count rows share the same X/Y/Z and
// mask grammar. Opcode and W choose the lane operation; only D/Q rows
// enable scalar-memory broadcast.
var x86RawVectorBitCountForms = [...]x86RawVectorBitCountForm{
	{op: "VPLZCNTD", opcode: 0x44},
	{op: "VPLZCNTQ", opcode: 0x44, w: true},
	{op: "VPOPCNTB", opcode: 0x54},
	{op: "VPOPCNTW", opcode: 0x54, w: true},
	{op: "VPOPCNTD", opcode: 0x55},
	{op: "VPOPCNTQ", opcode: 0x55, w: true},
}

func decodedX86RawVectorBitCountInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, recognized := decodeX86RawVectorEncoding(code)
	if !recognized || !p.evex || p.mapNumber != 2 || p.pp != 1 {
		return Instr{}, 0, false, nil
	}
	var form x86RawVectorBitCountForm
	for _, candidate := range x86RawVectorBitCountForms {
		if candidate.opcode == p.opcode && candidate.w == p.w {
			form = candidate
			break
		}
	}
	if form.op == "" {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("vector bit count: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if !p.fixed || p.upper != 0 || p.vectorLength > 2 {
		return fail("invalid reserved EVEX encoding bit")
	}
	if p.zero && p.mask == 0 {
		return fail("zeroing requires a nonzero mask")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	spec := amd64PackedBitCountSpecs[form.op]
	modRM := code[p.modRM]
	registerSource := modRM>>6 == 3
	if p.broadcast && (registerSource || !spec.broadcast) {
		return fail("broadcast requires a supported scalar-memory source")
	}
	if mode == 32 && !registerSource && (p.b != 0 || p.x != 0) {
		return fail("extended memory address in 32-bit mode")
	}

	vectorPrefix := [...]string{"X", "Y", "Z"}[p.vectorLength]
	vectorBytes := 16 << p.vectorLength
	registerNumber := int(modRM>>3&7) + p.r*8
	if mode == 32 && p.vectorLength == 2 && registerNumber >= 8 {
		return fail("386 Z destination register exceeds Go's encoder class")
	}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, registerNumber))}
	accessBytes := vectorBytes
	if p.broadcast {
		accessBytes = spec.laneBits / 8
	}
	source, consumed, err := decodedX86EVEXRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, vectorPrefix, accessBytes)
	if err != nil {
		return Instr{}, 0, true, err
	}
	op := form.op
	if p.broadcast {
		op += ".BCST"
	}
	if p.zero {
		op += ".Z"
	}
	args := []Operand{source}
	if p.mask != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", p.mask))})
	}
	args = append(args, destination)
	printed := make([]string, len(args))
	for index, arg := range args {
		printed[index] = arg.String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(printed, ", "))}, p.modRM + consumed, true, nil
}
