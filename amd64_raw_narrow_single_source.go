package plan9asm

import (
	"fmt"
	"strings"
)

// Go 1.27's _yvpmovdb/_yvpmovdw rows form a three-by-six grammar:
// unsigned-saturating, signed-saturating and truncating conversions, each
// narrowing W/D/Q into B/W/D. The low opcode nibble selects the width pair.
var x86RawSingleSourceNarrowOps = [3][6]Op{
	{"VPMOVUSWB", "VPMOVUSDB", "VPMOVUSQB", "VPMOVUSDW", "VPMOVUSQW", "VPMOVUSQD"},
	{"VPMOVSWB", "VPMOVSDB", "VPMOVSQB", "VPMOVSDW", "VPMOVSQW", "VPMOVSQD"},
	{"VPMOVWB", "VPMOVDB", "VPMOVQB", "VPMOVDW", "VPMOVQW", "VPMOVQD"},
}

func decodedX86SingleSourceNarrowInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, recognized := decodeX86RawVectorEncoding(code)
	if !recognized || !p.evex || p.mapNumber != 2 || p.pp != 2 {
		return Instr{}, 0, false, nil
	}
	group := p.opcode>>4 - 1
	width := p.opcode & 15
	if group < 0 || group >= len(x86RawSingleSourceNarrowOps) || width >= 6 {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("single-source narrowing: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if !p.fixed || p.w || p.upper != 0 || p.broadcast || p.vectorLength > 2 {
		return fail("invalid reserved EVEX encoding bit")
	}
	if p.zero && p.mask == 0 {
		return fail("zeroing requires a nonzero mask")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}

	baseOp := x86RawSingleSourceNarrowOps[group][width]
	spec := amd64SingleSourceNarrowSpecs[string(baseOp)]
	inputBytes := 16 << p.vectorLength
	outputBytes := inputBytes * spec.outputBits / spec.inputBits
	destinationPrefix := "X"
	if outputBytes > 16 {
		destinationPrefix = "Y"
	}
	modRM := code[p.modRM]
	registerNumber := int(modRM>>3&7) + p.r*8
	source := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", [...]string{"X", "Y", "Z"}[p.vectorLength], registerNumber))}
	if mode == 32 && p.vectorLength == 2 && registerNumber >= 8 {
		return fail("386 Z source register exceeds Go's encoder class")
	}
	if mode == 32 && modRM>>6 != 3 && (p.b != 0 || p.x != 0) {
		return fail("extended memory address in 32-bit mode")
	}
	destination, consumed, err := decodedX86EVEXRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, destinationPrefix, outputBytes)
	if err != nil {
		return Instr{}, 0, true, err
	}
	op := baseOp
	if p.zero {
		op += ".Z"
	}
	args := []Operand{source}
	if p.mask != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", p.mask))})
	}
	args = append(args, destination)
	printed := make([]string, len(args))
	for index, arg := range args {
		printed[index] = arg.String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(printed, ", "))}, p.modRM + consumed, true, nil
}
