package plan9asm

import "strings"

// Go calls Intel's legacy PMADDWD instruction PMADDWL. The raw decoder keeps
// that canonical spelling. ymm supplies MMX/m64 and X/m128; _yvandnpd supplies
// all VEX/EVEX widths. Each VPMADDWD row permits zeroing, never broadcasting.
var x86WordMultiplyAddSpecs = map[Op]x86PackedBinarySpec{
	"PMADDWL":  {encoding: x86PackedLogicalLegacyInteger},
	"VPMADDWD": {encoding: x86PackedLogicalVEXOrEVEX, zeroing: true},
}

type x86PackedMultiplyAddSpec struct {
	x86PackedBinarySpec
	inputBits, outputBits int
	nativeOpcode          string
}

var x86PackedMultiplyAddSpecs = map[Op]x86PackedMultiplyAddSpec{
	"PMADDWL":   {x86PackedBinarySpec{encoding: x86PackedLogicalLegacyInteger}, 16, 32, "pmaddwd"},
	"PMADDUBSW": {x86PackedBinarySpec{encoding: x86PackedLogicalLegacyFP}, 8, 16, "pmaddubsw"},
	"VPMADDWD":  {x86PackedBinarySpec{encoding: x86PackedLogicalVEXOrEVEX, zeroing: true}, 16, 32, ""},
	"VPMADDUBSW": {x86PackedBinarySpec{encoding: x86PackedLogicalVEXOrEVEX, zeroing: true},
		8, 16, ""},
}

type x86PackedMultiplyAddForm = x86PackedPhysicalForm

// This describes Go's actual ymm/yxm_q4/_yvandnpd operand rows only. WIG
// and the decoder's private physical marker do not grant a native address,
// initialized input, caller frame, or a new MMX transport.
func x86PackedMultiplyAddProperties(op Op, ins Instr, arch string) (x86PackedMultiplyAddForm, bool, error) {
	return x86PackedPhysicalProperties(op, ins, arch, x86PackedMultiplyAdd)
}

func x86WordMultiplyAddProperties(ins Instr, goarch string) (x86PackedBinaryForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	_, recognized := x86WordMultiplyAddSpecs[Op(base)]
	if !recognized {
		return x86PackedBinaryForm{}, false, nil
	}
	// Keep this word-only consumer boundary for the existing frame proof.
	form, known, err := x86PackedMultiplyAddProperties(ins.Op, ins, goarch)
	return form.x86PackedBinaryForm, known, err
}
