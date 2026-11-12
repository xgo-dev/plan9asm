package plan9asm

import "fmt"

type arm64RawSVEConvertEncoding struct {
	op              Op
	sourceBits      int
	destinationBits int
	zero            bool
}

// Go 1.27's predicated ZFCVT, ZFCVTZS, ZFCVTZU, ZSCVTF, and ZUCVTF
// encoder rows. The register fields share one typed conversion grammar;
// the fixed words enumerate only architecture-defined width/mode pairs.
var arm64RawSVEConvertEncodings = map[uint32]arm64RawSVEConvertEncoding{
	// ZFCVT
	0x65c8a000: {"ZFCVT", 64, 16, false},
	0x65caa000: {"ZFCVT", 64, 32, false},
	0x64da8000: {"ZFCVT", 64, 16, true},
	0x64dac000: {"ZFCVT", 64, 32, true},
	0x65c9a000: {"ZFCVT", 16, 64, false},
	0x6589a000: {"ZFCVT", 16, 32, false},
	0x64daa000: {"ZFCVT", 16, 64, true},
	0x649aa000: {"ZFCVT", 16, 32, true},
	0x65cba000: {"ZFCVT", 32, 64, false},
	0x6588a000: {"ZFCVT", 32, 16, false},
	0x64dae000: {"ZFCVT", 32, 64, true},
	0x649a8000: {"ZFCVT", 32, 16, true},

	// ZFCVTZS
	0x65dea000: {"ZFCVTZS", 64, 64, false},
	0x65d8a000: {"ZFCVTZS", 64, 32, false},
	0x64dfc000: {"ZFCVTZS", 64, 64, true},
	0x64de8000: {"ZFCVTZS", 64, 32, true},
	0x655ea000: {"ZFCVTZS", 16, 64, false},
	0x655aa000: {"ZFCVTZS", 16, 16, false},
	0x655ca000: {"ZFCVTZS", 16, 32, false},
	0x645fc000: {"ZFCVTZS", 16, 64, true},
	0x645ec000: {"ZFCVTZS", 16, 16, true},
	0x645f8000: {"ZFCVTZS", 16, 32, true},
	0x65dca000: {"ZFCVTZS", 32, 64, false},
	0x659ca000: {"ZFCVTZS", 32, 32, false},
	0x64df8000: {"ZFCVTZS", 32, 64, true},
	0x649f8000: {"ZFCVTZS", 32, 32, true},

	// ZFCVTZU
	0x65dfa000: {"ZFCVTZU", 64, 64, false},
	0x65d9a000: {"ZFCVTZU", 64, 32, false},
	0x64dfe000: {"ZFCVTZU", 64, 64, true},
	0x64dea000: {"ZFCVTZU", 64, 32, true},
	0x655fa000: {"ZFCVTZU", 16, 64, false},
	0x655ba000: {"ZFCVTZU", 16, 16, false},
	0x655da000: {"ZFCVTZU", 16, 32, false},
	0x645fe000: {"ZFCVTZU", 16, 64, true},
	0x645ee000: {"ZFCVTZU", 16, 16, true},
	0x645fa000: {"ZFCVTZU", 16, 32, true},
	0x65dda000: {"ZFCVTZU", 32, 64, false},
	0x659da000: {"ZFCVTZU", 32, 32, false},
	0x64dfa000: {"ZFCVTZU", 32, 64, true},
	0x649fa000: {"ZFCVTZU", 32, 32, true},

	// ZSCVTF
	0x65d6a000: {"ZSCVTF", 64, 64, false},
	0x6556a000: {"ZSCVTF", 64, 16, false},
	0x65d4a000: {"ZSCVTF", 64, 32, false},
	0x64ddc000: {"ZSCVTF", 64, 64, true},
	0x645dc000: {"ZSCVTF", 64, 16, true},
	0x64dd8000: {"ZSCVTF", 64, 32, true},
	0x6552a000: {"ZSCVTF", 16, 16, false},
	0x645cc000: {"ZSCVTF", 16, 16, true},
	0x65d0a000: {"ZSCVTF", 32, 64, false},
	0x6554a000: {"ZSCVTF", 32, 16, false},
	0x6594a000: {"ZSCVTF", 32, 32, false},
	0x64dc8000: {"ZSCVTF", 32, 64, true},
	0x645d8000: {"ZSCVTF", 32, 16, true},
	0x649d8000: {"ZSCVTF", 32, 32, true},

	// ZUCVTF
	0x65d7a000: {"ZUCVTF", 64, 64, false},
	0x6557a000: {"ZUCVTF", 64, 16, false},
	0x65d5a000: {"ZUCVTF", 64, 32, false},
	0x64dde000: {"ZUCVTF", 64, 64, true},
	0x645de000: {"ZUCVTF", 64, 16, true},
	0x64dda000: {"ZUCVTF", 64, 32, true},
	0x6553a000: {"ZUCVTF", 16, 16, false},
	0x645ce000: {"ZUCVTF", 16, 16, true},
	0x65d1a000: {"ZUCVTF", 32, 64, false},
	0x6555a000: {"ZUCVTF", 32, 16, false},
	0x6595a000: {"ZUCVTF", 32, 32, false},
	0x64dca000: {"ZUCVTF", 32, 64, true},
	0x645da000: {"ZUCVTF", 32, 16, true},
	0x649da000: {"ZUCVTF", 32, 32, true},
}

func decodeARM64RawSVEConvert(word uint32) (Instr, bool) {
	const registerFields = uint32(0x1fff)
	spec, ok := arm64RawSVEConvertEncodings[word&^registerFields]
	if !ok {
		return Instr{}, false
	}
	width := map[int]string{16: "H", 32: "S", 64: "D"}
	mode := "M"
	if spec.zero {
		mode = "Z"
	}
	source := int(word>>5) & 31
	predicate := int(word>>10) & 7
	destination := int(word) & 31
	return Instr{
		Op: spec.op,
		Args: []Operand{
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%s", source, width[spec.sourceBits]))},
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.%s", predicate, mode))},
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%s", destination, width[spec.destinationBits]))},
		},
		Raw: fmt.Sprintf("WORD $%#08x", word),
	}, true
}
