package plan9asm

import "fmt"

// decodeARM64RawSVEContiguousMemory covers the single-vector, scalar-base
// LD1B/ST1B and LD1H/ST1H grammar: signed MUL VL or scaled register offset,
// with every legal destination arrangement. It reuses the typed Go 1.27
// ordinary-memory lowerer for load extension and store truncation semantics.
func decodeARM64RawSVEContiguousMemory(word uint32) (Instr, bool) {
	const (
		registerBits  = uint32(0x007f1fff)
		immediateBits = uint32(0x006f1fff)
	)
	forms := [...]struct {
		op           Op
		register     uint32
		immediate    uint32
		load         bool
		elementBytes int64
		minimumWidth int
	}{
		{"ZLD1B", 0xa4004000, 0xa400a000, true, 1, 0},
		{"ZST1B", 0xe4004000, 0xe400e000, false, 1, 0},
		{"ZLD1H", 0xa4804000, 0xa480a000, true, 2, 1},
		{"ZST1H", 0xe4804000, 0xe480e000, false, 2, 1},
	}
	for _, form := range forms {
		registerOffset := word&^registerBits == form.register
		immediateOffset := word&^immediateBits == form.immediate
		if !registerOffset && !immediateOffset {
			continue
		}
		widthIndex := int(word>>21) & 3
		if widthIndex < form.minimumWidth {
			continue
		}
		baseNumber := int(word>>5) & 31
		base := Reg(fmt.Sprintf("R%d", baseNumber))
		if baseNumber == 31 {
			base = SP
		}
		memory := MemRef{Base: base}
		if registerOffset {
			indexNumber := int(word>>16) & 31
			index := Reg(fmt.Sprintf("R%d", indexNumber))
			if indexNumber == 31 {
				index = ZR
			}
			if form.elementBytes == 1 {
				// The unshifted Plan 9 memory spelling puts Xm first.
				memory.Base = index
				memory.Index = base
				memory.Scale = 1
			} else {
				memory.Index = index
				memory.Scale = form.elementBytes
			}
		} else {
			immediate := int(word>>16) & 15
			if immediate >= 8 {
				immediate -= 16
			}
			if immediate != 0 {
				if immediate < 0 {
					memory.OffRaw = fmt.Sprintf("-VL*%d", -immediate)
				} else {
					memory.OffRaw = fmt.Sprintf("VL*%d", immediate)
				}
			}
		}
		width := [...]string{"B", "H", "S", "D"}[widthIndex]
		vector := int(word) & 31
		predicate := int(word>>10) & 7
		list := Operand{
			Kind:    OpRegList,
			RegList: []Reg{Reg(fmt.Sprintf("Z%d.%s", vector, width))},
		}
		address := Operand{Kind: OpMem, Mem: memory}
		mode := ""
		if form.load {
			mode = ".Z"
		}
		governing := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d%s", predicate, mode))}
		args := []Operand{list, governing, address}
		if form.load {
			args = []Operand{address, governing, list}
		}
		return Instr{Op: form.op, Args: args, Raw: fmt.Sprintf("WORD $%#08x", word)}, true
	}
	return Instr{}, false
}
