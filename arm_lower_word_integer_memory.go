package plan9asm

import "fmt"

type armRawIntegerMemory struct {
	address        armIntegerMemoryForm
	base, transfer int
	condition      string
}

// The ordinary A32 word/byte transfers use an imm12 or a shifted register.
// Extra load/store encodings select an imm8 or an unshifted register and
// explicitly distinguish unsigned, signed-byte and signed-halfword loads.
// Keep that distinction before applying the common memory semantics.
func decodeARMRawIntegerMemory(word uint32) (armRawIntegerMemory, bool, error) {
	condition, validCondition := armRawCondition(word >> 28)
	if !validCondition {
		return armRawIntegerMemory{}, false, nil
	}
	load := word&(1<<20) != 0
	var spec armIntegerMemorySpec
	var offset Operand
	switch {
	case word&0x0c000000 == 0x04000000:
		spec.bits = 32
		if word&(1<<22) != 0 {
			spec.bits = 8
		}
		if word&(1<<25) == 0 {
			offset = Operand{Kind: OpImm, Imm: int64(word & 0xfff)}
		} else {
			if word&(1<<4) != 0 {
				return armRawIntegerMemory{}, false, nil // Media encoding space.
			}
			shifts := [...]ShiftOp{ShiftLeft, ShiftRight, ShiftArith, ShiftRotate}
			offset = Operand{
				Kind: OpRegShift, Reg: Reg(fmt.Sprintf("R%d", word&15)),
				ShiftOp: shifts[word>>5&3], ShiftAmount: int64(word >> 7 & 31),
			}
		}
	case word&0x0e000090 == 0x00000090:
		switch word >> 5 & 3 {
		case 1:
			spec.bits = 16
		case 2, 3:
			if !load {
				return armRawIntegerMemory{}, false, nil // LDRD/STRD.
			}
			spec = armIntegerMemorySpec{bits: 8 << (word >> 5 & 1), signed: true}
		default:
			return armRawIntegerMemory{}, false, nil
		}
		if word&(1<<22) != 0 {
			offset = Operand{Kind: OpImm, Imm: int64((word>>4)&0xf0 | word&0xf)}
		} else {
			if word&0xf00 != 0 {
				return armRawIntegerMemory{}, true, fmt.Errorf("invalid A32 extra load/store register offset in %#08x", word)
			}
			offset = Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("R%d", word&15))}
		}
	default:
		return armRawIntegerMemory{}, false, nil
	}

	base, transfer := int(word>>16&15), int(word>>12&15)
	postIndex := word&(1<<24) == 0
	write := word&(1<<21) != 0
	writeback := postIndex || write
	if postIndex && write {
		return armRawIntegerMemory{}, true, fmt.Errorf("%w: A32 unprivileged memory encoding %#08x needs an access-mode contract", ErrProbeNeedsContext, word)
	}
	if transfer == 15 && load {
		return armRawIntegerMemory{}, true, fmt.Errorf("%w: A32 load into PC in %#08x requires explicit control-flow context", ErrProbeNeedsContext, word)
	}
	if base == 15 || transfer == 15 || offset.Reg == "R15" {
		return armRawIntegerMemory{}, true, fmt.Errorf("%w: A32 memory encoding %#08x uses PC and requires source instruction layout context", ErrProbeNeedsContext, word)
	}
	if writeback && base == transfer {
		return armRawIntegerMemory{}, true, fmt.Errorf("invalid A32 memory writeback aliases transfer register in %#08x", word)
	}
	return armRawIntegerMemory{
		address: armIntegerMemoryForm{
			spec: spec, base: Reg(fmt.Sprintf("R%d", base)), reg: Reg(fmt.Sprintf("R%d", transfer)),
			offset: offset, load: load, postIndex: postIndex, writeback: writeback,
			subtract: word&(1<<23) == 0, encodedShift: offset.Kind == OpRegShift,
		},
		base: base, transfer: transfer, condition: condition,
	}, true, nil
}
