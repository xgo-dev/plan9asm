package plan9asm

import (
	"fmt"
	"strings"
)

type x86RawScaledRoundForm struct {
	op        Op
	laneBytes int
	scalar    bool
}

// Go 1.27's eight EVEX RNDSCALE/REDUCE opcode rows. Both operations share
// the same packed/scalar immediate and modifier grammar.
var x86RawScaledRoundForms = map[[2]int]x86RawScaledRoundForm{
	{0x08, 0}: {op: "VRNDSCALEPS", laneBytes: 4},
	{0x09, 1}: {op: "VRNDSCALEPD", laneBytes: 8},
	{0x0a, 0}: {op: "VRNDSCALESS", laneBytes: 4, scalar: true},
	{0x0b, 1}: {op: "VRNDSCALESD", laneBytes: 8, scalar: true},
	{0x56, 0}: {op: "VREDUCEPS", laneBytes: 4},
	{0x56, 1}: {op: "VREDUCEPD", laneBytes: 8},
	{0x57, 0}: {op: "VREDUCESS", laneBytes: 4, scalar: true},
	{0x57, 1}: {op: "VREDUCESD", laneBytes: 8, scalar: true},
}

func decodedX86RawScaledRoundInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || !p.evex || p.mapNumber != 3 || p.pp != 1 {
		return Instr{}, 0, false, nil
	}
	w := 0
	if p.w {
		w = 1
	}
	form, recognized := x86RawScaledRoundForms[[2]int{p.opcode, w}]
	if !recognized {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("EVEX scaled round: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if !p.fixed || p.addressOverride || p.vectorLength > 2 ||
		form.scalar && (mode == 32 || p.vectorLength != 0) ||
		!form.scalar && p.upper != 0 {
		return fail("invalid EVEX fixed, address, vector length, or vvvv")
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
	registerSource := modRM>>6 == 3
	sae := p.broadcast && registerSource
	broadcast := p.broadcast && !registerSource
	if form.scalar && broadcast || !form.scalar && sae && p.vectorLength != 2 {
		return fail("SAE or broadcast is unavailable for this operand width")
	}
	destinationNumber := int(modRM>>3&7) + p.r*8
	if mode == 32 && p.vectorLength == 2 &&
		(destinationNumber >= 8 || registerSource && int(modRM&7)+p.b*8+p.x*16 >= 8) {
		return fail("386 Z-register exceeds the Go assembler frontend's register class")
	}
	vector := [...]string{"X", "Y", "Z"}[p.vectorLength]
	disp8Scale := 16 << p.vectorLength
	if form.scalar || broadcast {
		disp8Scale = form.laneBytes
	}
	source, consumed, err := decodedX86EVEXRMOperand(
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
	if broadcast {
		op += ".BCST"
	}
	if sae {
		op += ".SAE"
	}
	if p.zero {
		op += ".Z"
	}
	args := []Operand{{Kind: OpImm, Imm: int64(code[immIndex])}, source}
	if form.scalar {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", p.upper))})
	}
	if p.mask != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", p.mask))})
	}
	args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vector, destinationNumber))})
	printed := make([]string, len(args))
	for index := range args {
		printed[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(printed, ", "))}, immIndex + 1, true, nil
}
