package plan9asm

import (
	"fmt"
	"strings"
)

// decodedX86RawVEXRoundInstruction implements Go's four VROUND PS/PD/SS/SD
// opcode rows. The packed forms reserve vvvv; scalar forms use it as their
// upper-lane source. Every form has a trailing imm8.
func decodedX86RawVEXRoundInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.mapNumber != 3 || p.pp != 1 || p.opcode < 0x08 || p.opcode > 0x0b {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("VROUND: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.evex || p.w || p.addressOverride {
		return fail("requires VEX.W0 without address override")
	}
	scalar := p.opcode >= 0x0a
	if scalar && p.vectorLength != 0 || !scalar && p.upper != 0 {
		return fail("invalid scalar vector length or packed reserved vvvv")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	destinationNumber := int(code[p.modRM]>>3&7) + p.r*8
	if mode == 32 && (destinationNumber >= 8 || p.upper >= 8 || p.b != 0 || p.x != 0) {
		return fail("extended register in 32-bit mode")
	}
	width := "X"
	if p.vectorLength != 0 {
		width = "Y"
	}
	source, consumed, err := decodedX86VEXVectorRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, width)
	if err != nil {
		return Instr{}, 0, true, err
	}
	immIndex := p.modRM + consumed
	if len(code) <= immIndex {
		return fail("missing imm8")
	}
	args := []Operand{{Kind: OpImm, Imm: int64(code[immIndex])}, source}
	if scalar {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", p.upper))})
	}
	args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, destinationNumber))})
	op := [...]Op{"VROUNDPS", "VROUNDPD", "VROUNDSS", "VROUNDSD"}[p.opcode-0x08]
	printed := make([]string, len(args))
	for index := range args {
		printed[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(printed, ", "))}, immIndex + 1, true, nil
}
