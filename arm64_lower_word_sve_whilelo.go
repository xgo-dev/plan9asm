package plan9asm

import "fmt"

// These are the four Go 1.27 encoder rows for each SVE predicate WHILE
// condition: scalar X, scalar W, predicate pair and SVE2.1 predicate counter.
// The raw decoder feeds the same typed grammar and lowering as named PWHILE*
// instructions instead of maintaining a second implementation of their flags.
type arm64RawSVEWhileSpec struct {
	condition string
	scalarX   uint32
	scalarW   uint32
	pair      uint32
	counter   uint32
}

var arm64RawSVEWhileSpecs = [...]arm64RawSVEWhileSpec{
	{"GE", 0x25201000, 0x25200000, 0x25205010, 0x25204010},
	{"GT", 0x25201010, 0x25200010, 0x25205011, 0x25204018},
	{"HI", 0x25201810, 0x25200810, 0x25205811, 0x25204818},
	{"HS", 0x25201800, 0x25200800, 0x25205810, 0x25204810},
	{"LE", 0x25201410, 0x25200410, 0x25205411, 0x25204418},
	{"LO", 0x25201c00, 0x25200c00, 0x25205c10, 0x25204c10},
	{"LS", 0x25201c10, 0x25200c10, 0x25205c11, 0x25204c18},
	{"LT", 0x25201400, 0x25200400, 0x25205410, 0x25204410},
}

func arm64RawSVEWhileGP(index uint32) Reg {
	if index == 31 {
		return ZR
	}
	return Reg(fmt.Sprintf("R%d", index))
}

func decodeARM64RawSVEWhile(word uint32) (Instr, bool) {
	width := "BHSD"[word>>22&3]
	// Go Plan 9 syntax lists Rm, Rn, then Pd. Raw AArch64 bits 5:9 encode
	// Rn and bits 16:20 encode Rm, so this reversal is intentional.
	args := []Operand{
		{Kind: OpReg, Reg: arm64RawSVEWhileGP(word >> 16 & 31)},
		{Kind: OpReg, Reg: arm64RawSVEWhileGP(word >> 5 & 31)},
	}
	for _, spec := range arm64RawSVEWhileSpecs {
		op := Op("PWHILE" + spec.condition)
		if word&0xff20fc10 == spec.scalarX || word&0xff20fc10 == spec.scalarW {
			if word&0x00001000 == 0 {
				op += "W"
			}
			args = append(args, Operand{
				Kind: OpReg,
				Reg:  Reg(fmt.Sprintf("P%d.%c", word&15, width)),
			})
			return Instr{Op: op, Args: args, Raw: fmt.Sprintf("WORD $%#08x", word)}, true
		}
		if word&0xff20fc11 == spec.pair {
			predicate := word & 14
			args = append(args, Operand{
				Kind: OpRegList,
				RegList: []Reg{
					Reg(fmt.Sprintf("P%d.%c", predicate, width)),
					Reg(fmt.Sprintf("P%d.%c", predicate+1, width)),
				},
			})
			return Instr{Op: op, Args: args, Raw: fmt.Sprintf("WORD $%#08x", word)}, true
		}
		if word&0xff20dc18 == spec.counter {
			multiplier := 2
			if word&0x2000 != 0 {
				multiplier = 4
			}
			args = append([]Operand{{Kind: OpIdent, Ident: fmt.Sprintf("VLX%d", multiplier)}}, args...)
			args = append(args, Operand{
				Kind: OpReg,
				Reg:  Reg(fmt.Sprintf("PN%d.%c", 8+(word&7), width)),
			})
			return Instr{Op: op, Args: args, Raw: fmt.Sprintf("WORD $%#08x", word)}, true
		}
	}
	return Instr{}, false
}
