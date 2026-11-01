package plan9asm

import "fmt"

type arm64SVELoadAddress uint8

const (
	arm64SVELoadRegister arm64SVELoadAddress = iota
	arm64SVELoadImmediate
	arm64SVELoadVectorOffset
	arm64SVELoadVectorBase
)

type arm64RawSVELoadRow struct {
	op          Op
	elementBits int
	address     arm64SVELoadAddress
	extension   ExtendOp
	scale       int64
}

var arm64RawSVELoadRows = arm64SVESignedLoadRawTable()

// LD1SB/SH/SW share the signed ordinary-load semantics. Expand only the
// encoding axes here: widening element size, scalar/vector address, index
// extension and scale. No opcode-specific lowering is needed.
func arm64SVESignedLoadRawTable() map[uint32]arm64RawSVELoadRow {
	rows := make(map[uint32]arm64RawSVELoadRow)
	for op, spec := range arm64SVEOrdinaryMemorySpecs {
		if !spec.load || !spec.signed {
			continue
		}
		memorySize := uint32(0)
		for 8<<memorySize < spec.memoryBits {
			memorySize++
		}
		for elementSize := memorySize + 1; elementSize < 4; elementSize++ {
			row := arm64RawSVELoadRow{op: op, elementBits: 8 << elementSize, scale: int64(spec.memoryBits / 8)}
			base := uint32(0xa5804000) - memorySize<<23 + (3-elementSize)<<21
			row.address = arm64SVELoadRegister
			rows[base] = row
			row.address = arm64SVELoadImmediate
			rows[base+0x6000] = row
			if elementSize < 2 {
				continue
			}
			vectorBase := uint32(0x84208000) + memorySize<<23
			if elementSize == 3 {
				vectorBase |= 1 << 30
			}
			row.address = arm64SVELoadVectorBase
			rows[vectorBase] = row
			row.address = arm64SVELoadVectorOffset
			for scale := uint32(0); scale < 2; scale++ {
				if memorySize == 0 && scale != 0 {
					continue
				}
				row.scale = 1 << (scale * memorySize)
				if elementSize == 3 {
					row.extension = ""
					rows[0xc4408000+memorySize<<23+scale<<21] = row
				}
				for signed, extension := range []ExtendOp{ExtendUXTW, ExtendSXTW} {
					row.extension = extension
					base := uint32(0x84000000) + memorySize<<23 + uint32(signed)<<22 + scale<<21
					if elementSize == 3 {
						base |= 1 << 30
					}
					rows[base] = row
				}
			}
		}
	}
	return rows
}

func decodeARM64RawSVESignedLoad(word uint32) (Instr, bool) {
	row, ok := arm64RawSVELoadRows[word&0xffe0e000]
	if !ok {
		return Instr{}, false
	}
	return decodeARM64RawSVELoadAddress(word, row)
}

// Both signed and unsigned loads normalize the same address grammar before
// using the ordinary-memory semantic lowerer.
func decodeARM64RawSVELoadAddress(word uint32, row arm64RawSVELoadRow) (Instr, bool) {
	base, index := word>>5&31, word>>16&31
	width := map[int]byte{8: 'B', 16: 'H', 32: 'S', 64: 'D', 128: 'Q'}[row.elementBits]
	memory := MemRef{Base: Reg(fmt.Sprintf("R%d", base))}
	if base == 31 {
		memory.Base = "RSP"
	}
	switch row.address {
	case arm64SVELoadRegister:
		if index == 31 { // Xm excludes 31; this is not a zero-index alias.
			return Instr{}, false
		}
		memory.Index, memory.Scale = Reg(fmt.Sprintf("R%d", index)), row.scale
		if row.scale == 1 {
			memory.Base, memory.Index = memory.Index, memory.Base
		}
	case arm64SVELoadImmediate:
		if index&16 != 0 {
			return Instr{}, false
		}
		offset := int(index)
		if offset >= 8 {
			offset -= 16
		}
		if offset < 0 {
			memory.OffRaw = fmt.Sprintf("-VL*%d", -offset)
		} else if offset > 0 {
			memory.OffRaw = fmt.Sprintf("VL*%d", offset)
		}
	case arm64SVELoadVectorOffset:
		memory.Index = Reg(fmt.Sprintf("Z%d.%c", index, width))
		memory.IndexExt, memory.Scale = row.extension, row.scale
	case arm64SVELoadVectorBase:
		memory.Base = Reg(fmt.Sprintf("Z%d.%c", base, width))
		memory.Off = int64(index) * row.scale
	}
	return Instr{Op: row.op, Raw: fmt.Sprintf("WORD $%#08x", word), Args: []Operand{
		{Kind: OpMem, Mem: memory},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.Z", word>>10&7))},
		{Kind: OpRegList, RegList: []Reg{Reg(fmt.Sprintf("Z%d.%c", word&31, width))}},
	}}, true
}
