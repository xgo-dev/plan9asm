package plan9asm

import (
	"fmt"
	"strings"
)

type x86RawMaskCompareForm struct {
	op        Op
	laneBytes int
}

// The eight signed and unsigned Go 1.27 _yvpcmpb opcode rows are selected
// by the opcode and EVEX.W, not by a separate decoder for each mnemonic.
var x86RawMaskCompareForms = map[[2]int]x86RawMaskCompareForm{
	{0x3f, 0}: {op: "VPCMPB", laneBytes: 1},
	{0x3f, 1}: {op: "VPCMPW", laneBytes: 2},
	{0x1f, 0}: {op: "VPCMPD", laneBytes: 4},
	{0x1f, 1}: {op: "VPCMPQ", laneBytes: 8},
	{0x3e, 0}: {op: "VPCMPUB", laneBytes: 1},
	{0x3e, 1}: {op: "VPCMPUW", laneBytes: 2},
	{0x1e, 0}: {op: "VPCMPUD", laneBytes: 4},
	{0x1e, 1}: {op: "VPCMPUQ", laneBytes: 8},
}

func decodedX86RawMaskCompareInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || !p.evex || p.mapNumber != 3 || p.pp != 1 {
		return Instr{}, 0, false, nil
	}
	w := 0
	if p.w {
		w = 1
	}
	form, recognized := x86RawMaskCompareForms[[2]int{p.opcode, w}]
	if !recognized {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("EVEX mask compare: %s", message)
	}
	if mode != 64 {
		return fail("Go's 386 assembler frontend cannot express mask compare operands")
	}
	if !p.fixed || p.addressOverride || p.vectorLength > 2 || p.zero || p.r != 0 {
		return fail("invalid EVEX fixed, address, vector length, zeroing, or K destination extension")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	modRM := code[p.modRM]
	if p.broadcast && (form.laneBytes < 4 || modRM>>6 == 3) {
		return fail("broadcast requires a D/Q scalar-memory first source")
	}
	vector := [...]string{"X", "Y", "Z"}[p.vectorLength]
	disp8Scale := 16 << p.vectorLength
	if p.broadcast {
		disp8Scale = form.laneBytes
	}
	first, consumed, err := decodedX86EVEXRMOperand(
		code[p.modRM:], mode, p.b, p.x, p.segment, vector, disp8Scale,
	)
	if err != nil {
		return Instr{}, 0, true, err
	}
	immIndex := p.modRM + consumed
	if len(code) <= immIndex {
		return fail("missing imm8")
	}
	op := form.op
	if p.broadcast {
		op += ".BCST"
	}
	args := []Operand{
		{Kind: OpImm, Imm: int64(code[immIndex])},
		first,
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vector, p.upper))},
	}
	if p.mask != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", p.mask))})
	}
	args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", modRM>>3&7))})
	printed := make([]string, len(args))
	for index := range args {
		printed[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(printed, ", "))}, immIndex + 1, true, nil
}
