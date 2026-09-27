package plan9asm

import (
	"fmt"
	"strings"
)

// Go 1.27's _yvpshufbitqmb forms are the product of test polarity (66/F3),
// B/W versus D/Q opcode, and EVEX.W. Each row has X/Y/Z widths and an
// optional K write-mask; only D/Q permits scalar-memory broadcast.
var x86RawPackedTestMaskOps = [2][2][2]Op{
	{
		{"VPTESTMB", "VPTESTMW"},
		{"VPTESTMD", "VPTESTMQ"},
	},
	{
		{"VPTESTNMB", "VPTESTNMW"},
		{"VPTESTNMD", "VPTESTNMQ"},
	},
}

func decodedX86RawPackedTestMaskInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, recognized := decodeX86RawVectorEncoding(code)
	if !recognized || !p.evex || p.mapNumber != 2 ||
		(p.pp != 1 && p.pp != 2) || (p.opcode != 0x26 && p.opcode != 0x27) {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("packed test mask: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if !p.fixed || p.vectorLength > 2 || p.r != 0 || p.zero {
		return fail("invalid reserved EVEX encoding bit")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	modRM := code[p.modRM]
	registerSource := modRM>>6 == 3
	if p.broadcast && (registerSource || p.opcode != 0x27) {
		return fail("broadcast requires a D/Q scalar-memory source")
	}
	if mode == 32 && !registerSource && (p.b != 0 || p.x != 0) {
		return fail("extended memory address in 32-bit mode")
	}

	polarity := p.pp - 1
	widthGroup := p.opcode - 0x26
	w := 0
	if p.w {
		w = 1
	}
	op := x86RawPackedTestMaskOps[polarity][widthGroup][w]
	laneBits := amd64PackedTestMaskSpecs[string(op)].laneBits
	vectorPrefix := [...]string{"X", "Y", "Z"}[p.vectorLength]
	accessBytes := 16 << p.vectorLength
	if p.broadcast {
		accessBytes = laneBits / 8
		op += ".BCST"
	}
	first, consumed, err := decodedX86EVEXRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, vectorPrefix, accessBytes)
	if err != nil {
		return Instr{}, 0, true, err
	}
	second := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, p.upper))}
	args := []Operand{first, second}
	if p.mask != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", p.mask))})
	}
	destination := modRM >> 3 & 7
	args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", destination))})
	printed := make([]string, len(args))
	for index, arg := range args {
		printed[index] = arg.String()
	}
	return Instr{
		Op:         op,
		Args:       args,
		Raw:        fmt.Sprintf("%s %s", op, strings.Join(printed, ", ")),
		x86Encoded: true,
	}, p.modRM + consumed, true, nil
}
