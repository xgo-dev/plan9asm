package plan9asm

import (
	"fmt"
	"strings"
)

// decodedX86RawPackedAbsInstruction implements Go's complete VPABS B/W/D/Q
// rows: VEX X/Y for B/W/D, EVEX X/Y/Z with optional K masking, and EVEX
// D/Q memory broadcast. VPABSQ is EVEX-only; W is fixed by the lane width.
func decodedX86RawPackedAbsInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.mapNumber != 2 || p.pp != 1 || p.opcode < 0x1c || p.opcode > 0x1f {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("VPABS: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if p.evex && !p.fixed || p.vectorLength > 2 || p.upper != 0 {
		return fail("invalid vector prefix or reserved vvvv bits")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	laneBytes := [...]int{1, 2, 4, 8}[p.opcode-0x1c]
	if p.w != (laneBytes == 8) || !p.evex && (laneBytes == 8 || p.vectorLength == 2) {
		return fail("invalid W bit or vector length for opcode")
	}
	if p.zero && p.mask == 0 {
		return fail("zeroing requires a nonzero mask")
	}
	registerSource := code[p.modRM]>>6 == 3
	if p.broadcast && (!p.evex || laneBytes < 4 || registerSource) {
		return fail("broadcast requires EVEX D/Q memory source")
	}
	width := [...]string{"X", "Y", "Z"}[p.vectorLength]
	scale := 16 << p.vectorLength
	if p.broadcast {
		scale = laneBytes
	}
	var source Operand
	var consumed int
	var err error
	if p.evex {
		source, consumed, err = decodedX86EVEXRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, width, scale)
	} else {
		source, consumed, err = decodedX86VEXVectorRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, width)
	}
	if err != nil {
		return Instr{}, 0, true, err
	}
	destinationNumber := int(code[p.modRM]>>3&7) + p.r*8
	if mode == 32 && (destinationNumber >= 8 || registerSource && (p.b != 0 || p.x != 0)) {
		return fail("extended register in 32-bit mode")
	}
	args := []Operand{source}
	if p.mask != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", p.mask))})
	}
	args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, destinationNumber))})
	op := Op("VPABS" + [...]string{"B", "W", "D", "Q"}[p.opcode-0x1c])
	if p.broadcast {
		op += ".BCST"
	}
	if p.zero {
		op += ".Z"
	}
	printed := make([]string, len(args))
	for index := range args {
		printed[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(printed, ", "))}, p.modRM + consumed, true, nil
}
