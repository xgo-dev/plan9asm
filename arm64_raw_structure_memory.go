package plan9asm

import "fmt"

// The Advanced SIMD multiple-structure, lane and replicate encoding groups
// share address/writeback fields. Keep register numbers until a consumer
// needs operands so layout proofs can use the form without building IR names.
type arm64RawStructureMemory struct {
	arrangement           arm64VectorArrangement
	count, lane           int
	firstRegister, base   int
	postRegister          int // 31 selects the fixed increment.
	load, post, replicate bool
	interleaved           bool
}

func decodeARM64RawStructureMemory(word uint32) (arm64RawStructureMemory, bool) {
	switch word & 0xbf000000 {
	case 0x0d000000:
		if word>>14&3 == 3 {
			return decodeARM64RawLDnR(word)
		}
		return decodeARM64RawStructureLane(word)
	case 0x0c000000:
		if word&(1<<21) != 0 {
			break
		}
		form, valid := arm64RawStructureAddress(word)
		if !valid {
			break
		}
		switch word >> 12 & 15 {
		case 0:
			form.count, form.interleaved = 4, true
		case 2:
			form.count = 4
		case 4:
			form.count, form.interleaved = 3, true
		case 6:
			form.count = 3
		case 7:
			form.count = 1
		case 8:
			form.count, form.interleaved = 2, true
		case 10:
			form.count = 2
		default:
			return arm64RawStructureMemory{}, false
		}
		if form.interleaved && form.arrangement.lanes == 1 {
			return arm64RawStructureMemory{}, false // Reserved Q=0, size=3.
		}
		return form, true
	}
	return arm64RawStructureMemory{}, false
}

func arm64RawStructureAddress(word uint32) (arm64RawStructureMemory, bool) {
	bits := 8 << (word >> 10 & 3)
	vectorBits := 64 << (word >> 30 & 1)
	form := arm64RawStructureMemory{
		arrangement:   arm64VectorArrangement{elementBits: bits, lanes: vectorBits / bits},
		lane:          -1,
		firstRegister: int(word & 31),
		base:          int(word >> 5 & 31),
		postRegister:  int(word >> 16 & 31),
		load:          word&(1<<22) != 0,
		post:          word&(1<<23) != 0,
	}
	return form, form.post || form.postRegister == 0
}

func decodeARM64RawLDnR(word uint32) (arm64RawStructureMemory, bool) {
	// Replicate encodes a load, opcode<2:1>=11 and S=0.
	if word&0xbf40d000 != 0x0d40c000 {
		return arm64RawStructureMemory{}, false
	}
	form, valid := arm64RawStructureAddress(word)
	if !valid {
		return arm64RawStructureMemory{}, false
	}
	form.count = 1 + int(word>>21&1) + 2*int(word>>13&1)
	form.replicate = true
	return form, true
}

func (raw arm64RawStructureMemory) width() int64 {
	return arm64StructureTransferBytes(raw.arrangement, raw.count, raw.lane >= 0 || raw.replicate)
}

func (raw arm64RawStructureMemory) baseRegister() Reg {
	if raw.base == 31 {
		return SP
	}
	return Reg(fmt.Sprintf("R%d", raw.base))
}

func (raw arm64RawStructureMemory) indexRegister() Reg {
	if raw.post && raw.postRegister != 31 {
		return Reg(fmt.Sprintf("R%d", raw.postRegister))
	}
	return ""
}

func (raw arm64RawStructureMemory) memoryForm() arm64StructureMemoryForm {
	form := arm64StructureMemoryForm{
		memory:      Operand{Kind: OpMem, Mem: MemRef{Base: raw.baseRegister()}},
		arrangement: raw.arrangement,
		load:        raw.load,
		replicate:   raw.replicate,
		interleaved: raw.interleaved,
		lane:        raw.lane,
		post:        raw.post,
		index:       raw.indexRegister(),
		registers:   make([]Reg, raw.count),
	}
	for i := range form.registers {
		form.registers[i] = Reg(fmt.Sprintf("V%d", (raw.firstRegister+i)%32))
	}
	if raw.post && form.index == "" {
		form.increment = raw.width()
	}
	return form
}
