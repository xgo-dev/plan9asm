package plan9asm

import (
	"fmt"
	"strings"
)

type x86RawEVEXUnpackForm struct {
	op             Op
	w              bool
	broadcastBytes int
}

// Go 1.27's eight EVEX integer interleave rows. Dword and QDQ sources may
// use scalar-memory broadcast; byte and word rows may not.
var x86RawEVEXUnpackForms = map[int]x86RawEVEXUnpackForm{
	0x60: {op: "VPUNPCKLBW"},
	0x61: {op: "VPUNPCKLWD"},
	0x62: {op: "VPUNPCKLDQ", broadcastBytes: 4},
	0x6c: {op: "VPUNPCKLQDQ", w: true, broadcastBytes: 8},
	0x68: {op: "VPUNPCKHBW"},
	0x69: {op: "VPUNPCKHWD"},
	0x6a: {op: "VPUNPCKHDQ", broadcastBytes: 4},
	0x6d: {op: "VPUNPCKHQDQ", w: true, broadcastBytes: 8},
}

func decodedX86EVEXPackedUnpackInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || !p.evex || p.mapNumber != 1 || p.pp != 1 {
		return Instr{}, 0, false, nil
	}
	form, recognized := x86RawEVEXUnpackForms[p.opcode]
	if !recognized {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("EVEX packed unpack: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if !p.fixed || p.w != form.w || p.addressOverride || p.vectorLength > 2 {
		return fail("invalid EVEX fixed, element width, address, or vector length")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if p.zero && p.mask == 0 {
		return fail("zeroing requires a nonzero mask")
	}
	if mode == 32 && p.mask != 0 {
		return fail("386 mask form exceeds the Go assembler frontend's operand limit")
	}
	modRM := code[p.modRM]
	if p.broadcast && (form.broadcastBytes == 0 || modRM>>6 == 3) {
		return fail("broadcast requires an enabled scalar-memory row")
	}
	destinationNumber := int(modRM>>3&7) + p.r*8
	if mode == 32 && p.vectorLength == 2 &&
		(destinationNumber >= 8 || p.upper >= 8 ||
			modRM>>6 == 3 && int(modRM&7)+p.b*8+p.x*16 >= 8) {
		return fail("386 Z-register exceeds the Go assembler frontend's register class")
	}
	vector := [...]string{"X", "Y", "Z"}[p.vectorLength]
	disp8Scale := 16 << p.vectorLength
	if p.broadcast {
		disp8Scale = form.broadcastBytes
	}
	first, consumed, err := decodedX86EVEXRMOperand(
		code[p.modRM:], mode, p.b, p.x, p.segment, vector, disp8Scale,
	)
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
	second := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vector, p.upper))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vector, destinationNumber))}
	args := []Operand{first, second}
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
