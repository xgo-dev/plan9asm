package plan9asm

import "fmt"

var arm64RawSVEUnsignedLoadRows = arm64SVEUnsignedLoadRawTable()

// Expand the ordinary load specification over the architectural address
// axes. Q-granule and multi-vector PN encodings have separate field layouts.
func arm64SVEUnsignedLoadRawTable() map[uint32]arm64RawSVELoadRow {
	rows := make(map[uint32]arm64RawSVELoadRow)
	for op, spec := range arm64SVEOrdinaryMemorySpecs {
		if !spec.load || spec.signed || spec.qOnly {
			continue
		}
		memorySize := uint32(0)
		for 8<<memorySize < spec.memoryBits {
			memorySize++
		}
		for elementSize := memorySize; elementSize < 4; elementSize++ {
			row := arm64RawSVELoadRow{op: op, elementBits: 8 << elementSize, scale: int64(spec.memoryBits / 8)}
			base := uint32(0xa4004000) + memorySize<<23 + elementSize<<21
			row.address = arm64SVELoadRegister
			rows[base] = row
			row.address = arm64SVELoadImmediate
			rows[base+0x6000] = row
			if elementSize < 2 {
				continue
			}
			vectorBase := uint32(0x8420c000) + memorySize<<23
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
					rows[0xc440c000+memorySize<<23+scale<<21] = row
				}
				for signed, extension := range []ExtendOp{ExtendUXTW, ExtendSXTW} {
					row.extension = extension
					base := uint32(0x84004000) + memorySize<<23 + uint32(signed)<<22 + scale<<21
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

func decodeARM64RawSVEUnsignedLoad(word uint32) (Instr, bool) {
	if row, ok := arm64RawSVEUnsignedLoadRows[word&0xffe0e000]; ok {
		return decodeARM64RawSVELoadAddress(word, row)
	}
	if decoded, ok := decodeARM64RawSVEPNLoad(word); ok {
		return decoded, true
	}
	if word&0xffe0e000 == 0xc400a000 {
		index := Reg(fmt.Sprintf("R%d", word>>16&31))
		if word>>16&31 == 31 {
			index = ZR
		}
		return Instr{Op: "ZLD1Q", Raw: fmt.Sprintf("WORD $%#08x", word), Args: []Operand{
			{Kind: OpMem, Mem: MemRef{Base: index, Index: Reg(fmt.Sprintf("Z%d.D", word>>5&31)), Scale: 1}},
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.Z", word>>10&7))},
			{Kind: OpRegList, RegList: []Reg{Reg(fmt.Sprintf("Z%d.Q", word&31))}},
		}}, true
	}
	for memorySize := uint32(2); memorySize < 4; memorySize++ {
		row := arm64RawSVELoadRow{
			op: Op("ZLD1" + string("BHWD"[memorySize])), elementBits: 128, scale: 1 << memorySize,
		}
		base := uint32(0xa4008000) + memorySize<<23
		if word&0xffe0e000 == base {
			row.address = arm64SVELoadRegister
			return decodeARM64RawSVELoadAddress(word, row)
		}
		if word&0xfff0e000 == base+0xfa000 {
			row.address = arm64SVELoadImmediate
			// Bit 20 is fixed, not the high bit of this signed imm4.
			ins, ok := decodeARM64RawSVELoadAddress(word&^(1<<20), row)
			ins.Raw = fmt.Sprintf("WORD $%#08x", word)
			return ins, ok
		}
	}
	return Instr{}, false
}

func decodeARM64RawSVEPNLoad(word uint32) (Instr, bool) {
	register := word&0xffe00000 == 0xa0000000
	immediate := word&0xfff00000 == 0xa0400000
	if !register && !immediate {
		return Instr{}, false
	}
	count := 2
	if word&(1<<15) != 0 {
		count = 4
	}
	destination := int(word & 31)
	if destination%count != 0 {
		return Instr{}, false
	}
	size := word >> 13 & 3
	base, index := word>>5&31, word>>16&31
	memory := MemRef{Base: Reg(fmt.Sprintf("R%d", base))}
	if base == 31 {
		memory.Base = "RSP"
	}
	if register && index != 31 {
		memory.Index, memory.Scale = Reg(fmt.Sprintf("R%d", index)), 1<<size
		if size == 0 {
			memory.Base, memory.Index = memory.Index, memory.Base
		}
	} else if immediate {
		offset := int(index)
		if offset >= 8 {
			offset -= 16
		}
		if offset < 0 {
			memory.OffRaw = fmt.Sprintf("-VL*%d", -offset*count)
		} else if offset > 0 {
			memory.OffRaw = fmt.Sprintf("VL*%d", offset*count)
		}
	}
	registers := make([]Reg, count)
	for i := range registers {
		registers[i] = Reg(fmt.Sprintf("Z%d.%c", destination+i, "BHSD"[size]))
	}
	return Instr{Op: Op("ZLD1" + string("BHWD"[size])), Raw: fmt.Sprintf("WORD $%#08x", word), Args: []Operand{
		{Kind: OpMem, Mem: memory},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("PN%d.Z", 8+(word>>10&7)))},
		{Kind: OpRegList, RegList: registers},
	}}, true
}

func (c *arm64Ctx) lowerRawSVEUnsignedLoad(ins Instr) error {
	if ins.Op == "ZLD1Q" && ins.Args[0].Mem.Base == ZR {
		bases, _, _ := arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: ins.Args[0].Mem.Index})
		predicate, _ := arm64ParseSVEPredicateMode(ins.Args[1], "Z", 7)
		vectors, _, _ := arm64ParseSVEOrdinaryVectorList(ins.Args[2])
		_, _, err := c.emitARM64SVEOrdinaryQGatherLoad(bases, predicate, vectors[0], "0")
		return err
	}
	_, _, err := c.lowerARM64SVEOrdinaryMemory(ins.Op, ins)
	return err
}
