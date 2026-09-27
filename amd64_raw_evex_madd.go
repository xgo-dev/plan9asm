package plan9asm

import (
	"fmt"
	"strings"
)

// decodedX86EVEXPackedMADDInstruction covers the EVEX rows of Go's
// _yvandnpd optab shared by VPMADDUBSW and VPMADDWD. Neither row permits
// EVEX.b broadcasting, but both permit K masks and zeroing at X/Y/Z widths.
func decodedX86EVEXPackedMADDInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || !p.evex || p.pp != 1 {
		return Instr{}, 0, false, nil
	}
	op := map[[2]int]Op{
		{1, 0xf5}: "VPMADDWD",
		{2, 0x04}: "VPMADDUBSW",
	}[[2]int{p.mapNumber, p.opcode}]
	if op == "" {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("EVEX packed multiply-add: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if !p.fixed || p.w || p.broadcast || p.addressOverride || p.vectorLength > 2 {
		return fail("invalid EVEX fixed, width, broadcast, address, or vector-length bits")
	}
	if p.zero && p.mask == 0 {
		return fail("zeroing requires a nonzero mask")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	modRM := code[p.modRM]
	destinationNumber := int(modRM>>3&7) + p.r*8
	if mode == 32 && (p.mask != 0 || p.upper >= 8 || destinationNumber >= 8 ||
		modRM>>6 == 3 && int(modRM&7)+p.b*8+p.x*16 >= 8) {
		return fail("extended vector register or mask in 32-bit mode")
	}
	vector := [...]string{"X", "Y", "Z"}[p.vectorLength]
	width := 16 << p.vectorLength
	first, consumed, err := decodedX86EVEXRMOperand(
		code[p.modRM:], mode, p.b, p.x, p.segment, vector, width,
	)
	if err != nil {
		return Instr{}, 0, true, err
	}
	second := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vector, p.upper))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vector, destinationNumber))}
	args := []Operand{first, second}
	if p.mask != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", p.mask))})
	}
	args = append(args, destination)
	if p.zero {
		op += ".Z"
	}
	printed := make([]string, len(args))
	for index := range args {
		printed[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(printed, ", "))}, p.modRM + consumed, true, nil
}
