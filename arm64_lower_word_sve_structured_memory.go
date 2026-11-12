package plan9asm

import (
	"fmt"
	"math/bits"
)

// The raw rows and the named grammar share count, element width and direction.
// Q-granule rows use a different count field from the ordinary B/H/S/D rows.
func (spec arm64SVEStructuredMemorySpec) rawBases() (register, immediate uint32) {
	count := uint32(spec.vectorCount - 1)
	if spec.q {
		if spec.load {
			return 0xa4208000 | count<<23, 0xa410e000 | count<<23
		}
		return 0xe4200000 | count<<22, 0xe4000000 | count<<22
	}
	size := uint32(bits.TrailingZeros(uint(spec.memoryBits)) - 3)
	fields := count<<21 | size<<23
	if spec.load {
		return 0xa400c000 | fields, 0xa400e000 | fields
	}
	return 0xe4006000 | fields, 0xe410e000 | fields
}

var arm64RawSVEStructuredRegisters, arm64RawSVEStructuredImmediates = arm64SVEStructuredRawTables()

func arm64SVEStructuredRawTables() (registers, immediates map[uint32]Op) {
	registers = make(map[uint32]Op, len(arm64SVEStructuredMemorySpecs))
	immediates = make(map[uint32]Op, len(arm64SVEStructuredMemorySpecs))
	for op, spec := range arm64SVEStructuredMemorySpecs {
		register, immediate := spec.rawBases()
		registers[register] = op
		immediates[immediate] = op
	}
	return
}

func decodeARM64RawSVEStructuredMemory(word uint32) (Instr, bool) {
	op, registerOffset := arm64RawSVEStructuredRegisters[word&0xffe0e000]
	if !registerOffset {
		var ok bool
		op, ok = arm64RawSVEStructuredImmediates[word&0xfff0e000]
		if !ok {
			return Instr{}, false
		}
	}
	spec := arm64SVEStructuredMemorySpecs[op]
	base := Reg(fmt.Sprintf("R%d", word>>5&31))
	if word>>5&31 == 31 {
		base = "RSP"
	}
	memory := MemRef{Base: base}
	if registerOffset {
		index := word >> 16 & 31
		if index == 31 { // Rm=31 is not allocated in scalar-index forms.
			return Instr{}, false
		}
		memory.Index = Reg(fmt.Sprintf("R%d", index))
		memory.Scale = int64(spec.memoryBits / 8)
		if spec.memoryBits == 8 {
			// The unshifted Plan 9 spelling writes (Xm)(Xn|RSP).
			memory.Base, memory.Index = memory.Index, memory.Base
		}
	} else {
		offset := int(word >> 16 & 15)
		if offset >= 8 {
			offset -= 16
		}
		offset *= spec.vectorCount
		if offset < 0 {
			memory.OffRaw = fmt.Sprintf("-VL*%d", -offset)
		} else if offset > 0 {
			memory.OffRaw = fmt.Sprintf("VL*%d", offset)
		}
	}
	width := map[int]string{8: "B", 16: "H", 32: "S", 64: "D", 128: "Q"}[spec.memoryBits]
	list := Operand{Kind: OpRegList}
	for i := 0; i < spec.vectorCount; i++ {
		list.RegList = append(list.RegList, Reg(fmt.Sprintf("Z%d.%s", (int(word&31)+i)%32, width)))
	}
	mode := ""
	if spec.load {
		mode = ".Z"
	}
	predicate := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d%s", word>>10&7, mode))}
	address := Operand{Kind: OpMem, Mem: memory}
	args := []Operand{list, predicate, address}
	if spec.load {
		args = []Operand{address, predicate, list}
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("WORD $%#08x", word)}, true
}
