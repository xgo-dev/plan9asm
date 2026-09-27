package plan9asm

import (
	"fmt"
	"strings"
)

// decodedX86RawEVEXFloatLogicalInstruction covers Go 1.27's EVEX
// VAND/ANDN/OR/XOR PS/PD rows across X/Y/Z, masks, and scalar broadcast.
func decodedX86RawEVEXFloatLogicalInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || !p.evex || p.mapNumber != 1 || p.opcode < 0x54 || p.opcode > 0x57 {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("EVEX floating logical: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if !p.fixed || p.addressOverride || p.vectorLength > 2 || p.pp > 1 || p.w != (p.pp == 1) {
		return fail("invalid prefix or vector length")
	}
	if p.zero && p.mask == 0 {
		return fail("zeroing requires K1-K7")
	}
	if mode == 32 && p.mask != 0 {
		return fail("386 masked form exceeds Go's three-operand frontend")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if p.broadcast && code[p.modRM]>>6 == 3 {
		return fail("broadcast requires a memory source")
	}
	width := [...]string{"X", "Y", "Z"}[p.vectorLength]
	scale := 16 << p.vectorLength
	if p.broadcast {
		scale = 4
		if p.w {
			scale = 8
		}
	}
	source, consumed, err := decodedX86EVEXRMOperand(
		code[p.modRM:], mode, p.b, p.x, p.segment, width, scale,
	)
	if err != nil {
		return Instr{}, 0, true, err
	}
	stem := [...]string{"VAND", "VANDN", "VOR", "VXOR"}[p.opcode-0x54]
	suffix := "PS"
	if p.w {
		suffix = "PD"
	}
	op := Op(stem + suffix)
	if p.broadcast {
		op += ".BCST"
	}
	if p.zero {
		op += ".Z"
	}
	second := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, p.upper))}
	destNumber := int(code[p.modRM]>>3&7) + p.r*8
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, destNumber))}
	args := []Operand{source, second}
	if p.mask != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", p.mask))})
	}
	args = append(args, destination)
	printed := make([]string, len(args))
	for index, arg := range args {
		printed[index] = arg.String()
	}
	return Instr{
		Op: op, Args: args,
		Raw:        fmt.Sprintf("%s %s", op, strings.Join(printed, ", ")),
		x86Encoded: true,
	}, p.modRM + consumed, true, nil
}
