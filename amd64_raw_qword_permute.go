package plan9asm

import (
	"fmt"
	"strings"
)

// Go's _yvpermq table gives VPERMQ and VPERMPD the same operand grammar.
// The 0F3A encodings use imm8 control; the EVEX-only 0F38 encodings use a
// vector control operand. The table below keeps the opcode split explicit.
var x86RawQwordPermutes = map[[2]int]Op{
	{3, 0x00}: "VPERMQ",
	{3, 0x01}: "VPERMPD",
	{2, 0x36}: "VPERMQ",
	{2, 0x16}: "VPERMPD",
}

func decodedX86RawQwordPermuteInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.pp != 1 || !p.w {
		return Instr{}, 0, false, nil
	}
	op, known := x86RawQwordPermutes[[2]int{p.mapNumber, p.opcode}]
	if !known {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("qword permute: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if p.vectorLength < 1 || p.vectorLength > 2 || !p.evex && p.vectorLength != 1 {
		return fail("only Y and Z vector lengths are in Go's qword permute table")
	}
	if p.evex && !p.fixed {
		return fail("invalid EVEX fixed bit")
	}
	if p.zero && p.mask == 0 {
		return fail("zeroing requires a nonzero mask")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	immediate := p.mapNumber == 3
	if !immediate && !p.evex {
		return fail("variable-control form requires EVEX")
	}
	if immediate && p.upper != 0 {
		return fail("immediate form reserves vvvv and V'")
	}
	registerSource := code[p.modRM]>>6 == 3
	if p.broadcast && (registerSource || !p.evex) {
		return fail("broadcast requires EVEX memory source")
	}
	width := [...]string{"X", "Y", "Z"}[p.vectorLength]
	destinationNumber := int(code[p.modRM]>>3&7) + p.r*8
	if mode == 32 && (!p.evex && destinationNumber >= 8 ||
		width == "Z" && (destinationNumber >= 8 || !immediate && p.upper >= 8)) {
		return fail("destination or control register unavailable in 32-bit mode")
	}

	scale := 16 << p.vectorLength
	if p.broadcast {
		scale = 8
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
	if mode == 32 && width == "Z" && source.Kind == OpReg {
		index, _ := amd64VectorRegisterIndex(source.Reg, 64)
		if index >= 8 {
			return fail("Z source register unavailable in 32-bit mode")
		}
	}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, destinationNumber))}
	args := make([]Operand, 0, 4)
	if immediate {
		if len(code) <= p.modRM+consumed {
			return fail("missing immediate byte")
		}
		args = append(args, Operand{Kind: OpImm, Imm: int64(code[p.modRM+consumed])})
	} else {
		args = append(args, source)
		source = Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, p.upper))}
	}
	args = append(args, source)
	if p.mask != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", p.mask))})
	}
	args = append(args, destination)
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
	length := p.modRM + consumed
	if immediate {
		length++
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(printed, ", "))}, length, true, nil
}
