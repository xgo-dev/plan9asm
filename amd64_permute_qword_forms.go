package plan9asm

import "strings"

// Both members share all ten Go _yvpermq rows. Immediate control repeats
// within each 256-bit block; variable control selects from the full vector.
var x86QwordPermuteBits = map[Op]int{"VPERMQ": 64, "VPERMPD": 64}

func x86QwordPermuteProperties(op Op, ins Instr, arch string) (x86ElementPermuteForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	bits, known := x86QwordPermuteBits[Op(base)]
	if !known {
		return x86ElementPermuteForm{}, false, nil
	}
	return x86ElementPermuteFormProperties(op, ins, arch, bits, true)
}
