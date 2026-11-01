package plan9asm

import "fmt"

type arm64RawSVEIntegerDotRow struct {
	op      Op
	width   int
	indexed bool
}

var arm64RawSVEIntegerDotRows, arm64RawSVEIntegerDotBytePairRows = arm64SVEIntegerDotRawTables()

func arm64SVEIntegerDotRawTables() (ordinary, bytePairs map[uint32]arm64RawSVEIntegerDotRow) {
	ordinary = make(map[uint32]arm64RawSVEIntegerDotRow)
	bytePairs = make(map[uint32]arm64RawSVEIntegerDotRow)
	for op, spec := range arm64SVEIntegerDotSpecs {
		for width, bases := range spec.rawBases {
			for indexed, base := range bases {
				if base == 0 {
					continue
				}
				row := arm64RawSVEIntegerDotRow{op, width, indexed != 0}
				if width == 0 && row.indexed {
					bytePairs[base] = row
				} else {
					ordinary[base] = row
				}
			}
		}
	}
	return
}

func decodeARM64RawSVEIntegerDot(word uint32) (Instr, bool) {
	row, ok := arm64RawSVEIntegerDotRows[word&0xffe0fc00]
	if !ok {
		row, ok = arm64RawSVEIntegerDotBytePairRows[word&0xffa0fc00]
		if !ok {
			return Instr{}, false
		}
	}
	widths := arm64SVEIntegerDotWidthForms[row.width]
	first, index := word>>16&31, ""
	if row.indexed {
		first &= uint32(widths.maximumVector)
		lane := word >> 19 & 3
		if widths.destination == 16 {
			lane |= word >> 20 & 4
		} else if widths.destination == 64 {
			lane = word >> 20 & 1
		}
		index = fmt.Sprintf("[%d]", lane)
	}
	sourceWidth, destinationWidth := "B", "S"
	if widths.source == 16 {
		sourceWidth = "H"
	}
	if widths.destination == 16 {
		destinationWidth = "H"
	} else if widths.destination == 64 {
		destinationWidth = "D"
	}
	return Instr{Op: row.op, Raw: fmt.Sprintf("WORD $%#08x", word), Args: []Operand{
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%s%s", first, sourceWidth, index))},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%s", word>>5&31, sourceWidth))},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%s", word&31, destinationWidth))},
	}}, true
}
