package plan9asm

import "fmt"

type arm64RawSVEMultiplyAccumulateRow struct {
	op   Op
	size uint32
}

var arm64RawSVEMultiplyAccumulatePredicatedOps, arm64RawSVEMultiplyAccumulateIndexedRows = arm64SVEMultiplyAccumulateRawTables()

func arm64SVEMultiplyAccumulateRawTables() (map[uint32]Op, map[uint32]arm64RawSVEMultiplyAccumulateRow) {
	predicated := make(map[uint32]Op)
	indexed := make(map[uint32]arm64RawSVEMultiplyAccumulateRow)
	for op, spec := range arm64SVEMultiplyAccumulateSpecs {
		predicated[spec.predicatedRaw] = op
		for size, base := range spec.indexedRaw {
			if base == 0 {
				continue
			}
			indexed[base] = arm64RawSVEMultiplyAccumulateRow{op, uint32(size + 1)}
		}
	}
	return predicated, indexed
}

func decodeARM64RawSVEMultiplyAccumulate(word uint32) (Instr, bool) {
	op, predicated := arm64RawSVEMultiplyAccumulatePredicatedOps[word&0xff20e000]
	size, multiplier, lane := word>>22&3, word>>16&31, ""
	if !predicated {
		// Halfword lane[2] replaces size[0]; word and doubleword retain
		// their fixed size bits. Never let those forms alias the H decoder.
		row, ok := arm64RawSVEMultiplyAccumulateIndexedRows[word&0xffe0fc00]
		if !ok {
			row, ok = arm64RawSVEMultiplyAccumulateIndexedRows[word&0xffa0fc00]
			if !ok || row.size != 1 {
				return Instr{}, false
			}
		}
		op, size = row.op, row.size
		index := word >> 19 & 3
		multiplier &= 7
		if size == 1 {
			index |= word >> 20 & 4
		} else if size == 3 {
			multiplier = word >> 16 & 15
			index = word >> 20 & 1
		}
		lane = fmt.Sprintf("[%d]", index)
	}
	width := "BHSD"[size]
	args := []Operand{
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c%s", multiplier, width, lane))},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", word>>5&31, width))},
	}
	if arm64SVEMultiplyAccumulateSpecs[op].destructiveProduct {
		// MAD/MSB encode the addend in bits 9:5, unlike MLA/MLS's
		// multiplicand. Normalize both encodings to Go's operand order.
		args[0], args[1] = args[1], args[0]
	}
	if predicated {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.M", word>>10&7))})
	}
	args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", word&31, width))})
	return Instr{Op: op, Raw: fmt.Sprintf("WORD $%#08x", word), Args: args}, true
}
