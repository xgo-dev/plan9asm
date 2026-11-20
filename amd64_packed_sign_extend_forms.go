package plan9asm

import "strings"

// Keep all twelve signed members separate from the pre-existing unsigned
// inventory: sharing pure grammar must not extend its raw-source identity.
var x86PackedSignExtendSpecs = map[Op]x86PackedExtendSpec{
	"PMOVSXBW":  {8, 16, false, 0x20},
	"PMOVSXBD":  {8, 32, false, 0x21},
	"PMOVSXBQ":  {8, 64, false, 0x22},
	"PMOVSXWD":  {16, 32, false, 0x23},
	"PMOVSXWQ":  {16, 64, false, 0x24},
	"PMOVSXDQ":  {32, 64, false, 0x25},
	"VPMOVSXBW": {8, 16, true, 0x20},
	"VPMOVSXBD": {8, 32, true, 0x21},
	"VPMOVSXBQ": {8, 64, true, 0x22},
	"VPMOVSXWD": {16, 32, true, 0x23},
	"VPMOVSXWQ": {16, 64, true, 0x24},
	"VPMOVSXDQ": {32, 64, true, 0x25},
}

func x86PackedSignExtendProperties(ins Instr, arch string) (x86PackedExtendForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	if _, known := x86PackedSignExtendSpecs[Op(base)]; !known {
		return x86PackedExtendForm{}, false, nil
	}
	return x86PackedExtendProperties(ins, arch)
}
