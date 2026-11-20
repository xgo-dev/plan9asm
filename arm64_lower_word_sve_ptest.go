package plan9asm

import "fmt"

// PTEST has one byte-granularity form; both predicate numbers are four-bit
// fields. Route the raw encoding through the named flag-producing lowerer.
func decodeARM64RawSVEPTest(word uint32) (Instr, bool) {
	if word&0xffffc21f != 0x2550c000 {
		return Instr{}, false
	}
	tested := Reg(fmt.Sprintf("P%d.B", word>>5&15))
	governing := Reg(fmt.Sprintf("P%d", word>>10&15))
	return Instr{
		Op:   "PPTEST",
		Args: []Operand{{Kind: OpReg, Reg: tested}, {Kind: OpReg, Reg: governing}},
		Raw:  fmt.Sprintf("WORD $%#08x", word),
	}, true
}
