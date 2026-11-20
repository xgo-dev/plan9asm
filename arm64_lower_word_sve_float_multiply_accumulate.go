package plan9asm

import "fmt"

// Go 1.27 exposes all eight predicated fused floating-point multiply forms
// with the same register fields. The first two source operands have a different
// field order for the accumulating (MLA/MLS) and destructive (MAD/MSB) forms.
var arm64RawSVEFloatMultiplyAccumulateBases = map[uint32]Op{
	0x65208000: "ZFMAD",
	0x65200000: "ZFMLA",
	0x65202000: "ZFMLS",
	0x6520a000: "ZFMSB",
	0x6520c000: "ZFNMAD",
	0x65204000: "ZFNMLA",
	0x65206000: "ZFNMLS",
	0x6520e000: "ZFNMSB",
}

func decodeARM64RawSVEFloatMultiplyAccumulate(word uint32) (Instr, bool) {
	const variableFields = uint32(0x00df1fff)
	op, ok := arm64RawSVEFloatMultiplyAccumulateBases[word&^variableFields]
	if !ok {
		return Instr{}, false
	}
	width := map[uint32]string{1: "H", 2: "S", 3: "D"}[word>>22&3]
	if width == "" {
		return Instr{}, false
	}
	first := word >> 16 & 31
	second := word >> 5 & 31
	switch op {
	case "ZFMAD", "ZFMSB", "ZFNMAD", "ZFNMSB":
		first, second = second, first
	}
	predicate := word >> 10 & 7
	destination := word & 31
	return Instr{
		Op: op,
		Args: []Operand{
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%s", first, width))},
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%s", second, width))},
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.M", predicate))},
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%s", destination, width))},
		},
		Raw: fmt.Sprintf("WORD $%#08x", word),
	}, true
}
