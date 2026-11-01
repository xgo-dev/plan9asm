package plan9asm

import "fmt"

// Derive the raw lookup tables from the same family specs used by named
// validation and lowering. Immediate and reverse-vector operands share the
// predicated mask, but use different interpretations of bits 9:5.
var arm64SVEExtraShiftPredicated, arm64SVEExtraShiftUnpredicated = arm64SVEExtraShiftRawTables()

func arm64SVEExtraShiftRawTables() (map[uint32]Op, map[uint32]Op) {
	predicated, unpredicated := make(map[uint32]Op), make(map[uint32]Op)
	for op, spec := range arm64SVEImmediateShiftSpecs {
		if spec.predicated {
			predicated[spec.rawBase] = op
		} else {
			unpredicated[spec.rawBase] = op
		}
	}
	for op, spec := range arm64SVEReverseShiftIntrinsics {
		predicated[spec.rawBase] = op
	}
	return predicated, unpredicated
}

func decodeARM64RawSVEExtraShift(word uint32) (Instr, bool) {
	op, predicated := arm64SVEExtraShiftPredicated[word&0xff3fe000]
	lowBit := 5
	if !predicated {
		var ok bool
		op, ok = arm64SVEExtraShiftUnpredicated[word&0xff20fc00]
		if !ok {
			return Instr{}, false
		}
		lowBit = 16
	}
	_, reverse := arm64SVEReverseShiftIntrinsics[op]
	elementBits, shift, valid := decodeARM64SVEShiftImmediate(word, lowBit)
	if reverse {
		elementBits = 8 << (word >> 22 & 3)
	} else if !valid {
		return Instr{}, false
	} else if arm64SVEImmediateShiftSpecs[op].minimum == 0 {
		shift = elementBits - shift
	}
	width := map[int]byte{8: 'B', 16: 'H', 32: 'S', 64: 'D'}[elementBits]
	reg := func(number uint32) Operand {
		return Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", number, width))}
	}
	destination := reg(word & 31)
	first := Operand{Kind: OpImm, Imm: int64(shift)}
	if reverse {
		first = reg(word >> 5 & 31)
	}
	args := []Operand{first}
	if predicated {
		args = append(args, destination, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.M", word>>10&7))})
	} else {
		args = append(args, reg(word>>5&31))
	}
	args = append(args, destination)
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("WORD $%#08x", word)}, true
}

func (c *arm64Ctx) lowerARM64RawSVEExtraShift(ins Instr) error {
	spec, immediate := arm64SVEImmediateShiftSpecs[ins.Op]
	if !immediate {
		_, _, err := c.lowerARM64SVEExtraShift(ins.Op, ins)
		return err
	}
	source, bits, _ := arm64ParseSVEZElementReg(ins.Args[1])
	destination, _, _ := arm64ParseSVEZElementReg(ins.Args[len(ins.Args)-1])
	predicate := 0
	if spec.predicated {
		predicate, _ = arm64ParseSVEPredicateMerge(ins.Args[2])
	}
	// Arm WORD encodings allow right shifts by the full element width;
	// Go's named immediate grammar intentionally retains its tighter bound.
	return c.lowerARM64SVEExtraImmediateShiftForm(spec, bits, source, destination, predicate, ins.Args[0].Imm)
}
