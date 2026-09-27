package plan9asm

import (
	"fmt"
	"strings"
)

// Go 1.27's four VPACK rows share the same three-operand grammar. The two
// dword-to-word operations also permit EVEX 32-bit memory broadcast.
var x86RawPackedNarrowOps = map[[2]int]struct {
	op        Op
	broadcast bool
}{
	{1, 0x6b}: {op: "VPACKSSDW", broadcast: true},
	{1, 0x63}: {op: "VPACKSSWB"},
	{2, 0x2b}: {op: "VPACKUSDW", broadcast: true},
	{1, 0x67}: {op: "VPACKUSWB"},
}

func decodedX86VectorPackedSaturatingNarrowInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched {
		return Instr{}, 0, false, nil
	}
	spec, known := x86RawPackedNarrowOps[[2]int{p.mapNumber, p.opcode}]
	if !known {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("packed saturating narrow: %s", message)
	}
	if mode != 64 {
		return fail("Go vector PACK forms require amd64")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if p.pp != 1 || p.w || p.vectorLength > 2 {
		return fail("invalid prefix, width or vector length")
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
	registerSource := code[p.modRM]>>6 == 3
	if p.broadcast && (!spec.broadcast || registerSource) {
		return fail("broadcast requires a dword-to-word memory source")
	}
	width := [...]string{"X", "Y", "Z"}[p.vectorLength]
	scale := 16 << p.vectorLength
	if p.broadcast {
		scale = 4
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
	secondSource := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, p.upper))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, int(code[p.modRM]>>3&7)+p.r*8))}
	args := []Operand{source, secondSource}
	op := spec.op
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
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(printed, ", "))}, p.modRM + consumed, true, nil
}
