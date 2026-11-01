package plan9asm

import (
	"fmt"
	"strings"
)

// decodedX86RawVariableRotateInstruction covers the four EVEX per-lane
// variable rotates in Go's _yvblendmpd table: left/right, D/Q, X/Y/Z,
// optional mask, zeroing, and scalar-memory broadcast.
func decodedX86RawVariableRotateInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || !p.evex || p.mapNumber != 2 || p.pp != 1 ||
		(p.opcode != 0x14 && p.opcode != 0x15) {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("EVEX variable rotate: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if !p.fixed || p.addressOverride || p.vectorLength > 2 {
		return fail("invalid EVEX fixed, address, or vector-length bits")
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
	if p.broadcast && modRM>>6 == 3 {
		return fail("EVEX.b broadcast requires memory")
	}
	destinationNumber := int(modRM>>3&7) + p.r*8
	if mode == 32 && (p.upper >= 8 || destinationNumber >= 8 ||
		modRM>>6 == 3 && int(modRM&7)+p.b*8+p.x*16 >= 8) {
		return fail("extended vector register in 32-bit mode")
	}
	vector := [...]string{"X", "Y", "Z"}[p.vectorLength]
	width := 16 << p.vectorLength
	laneBytes := 4
	if p.w {
		laneBytes = 8
	}
	disp8Scale := width
	if p.broadcast {
		disp8Scale = laneBytes
	}
	first, consumed, err := decodedX86EVEXRMOperand(
		code[p.modRM:], mode, p.b, p.x, p.segment, vector, disp8Scale,
	)
	if err != nil {
		return Instr{}, 0, true, err
	}
	op := Op("VPRORVD")
	if p.opcode == 0x15 {
		op = "VPROLVD"
	}
	if p.w {
		op = Op(strings.TrimSuffix(string(op), "D") + "Q")
	}
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
