package plan9asm

import "fmt"

// SVE SADALP/UADALP widen adjacent source lanes and accumulate into the
// predicated destination. Size chooses B-to-H, H-to-S, or S-to-D.
func decodeARM64RawSVEAddPairwiseLong(word uint32) (Instr, bool) {
	if word&0xff3ee000 != 0x4404a000 {
		return Instr{}, false
	}
	width := int(word>>22) & 3
	if width == 0 {
		return Instr{}, false
	}
	op := Op("ZSADALP")
	if word&(1<<16) != 0 {
		op = "ZUADALP"
	}
	arrangements := [...]string{"", "B", "H", "S", "D"}
	source := Reg(fmt.Sprintf("Z%d.%s", word>>5&31, arrangements[width]))
	predicate := Reg(fmt.Sprintf("P%d.M", word>>10&7))
	destination := Reg(fmt.Sprintf("Z%d.%s", word&31, arrangements[width+1]))
	return Instr{
		Op: op,
		Args: []Operand{
			{Kind: OpReg, Reg: source},
			{Kind: OpReg, Reg: predicate},
			{Kind: OpReg, Reg: destination},
		},
		Raw: fmt.Sprintf("WORD $%#08x", word),
	}, true
}
