package plan9asm

import "fmt"

type arm64RawUMLAL struct {
	highHalf    bool
	source      arm64VectorArrangement
	destination arm64VectorArrangement
	destReg     int
	first       int
	second      int
}

func decodeARM64RawUMLAL(word uint32) (arm64RawUMLAL, bool) {
	if word&0xbf20fc00 != 0x2e208000 {
		return arm64RawUMLAL{}, false
	}
	size := int(word>>22) & 3
	if size > 2 {
		return arm64RawUMLAL{}, false
	}
	sourceBits := 8 << size
	destinationLanes := 128 / (sourceBits * 2)
	highHalf := word&(1<<30) != 0
	sourceLanes := destinationLanes
	if highHalf {
		sourceLanes *= 2
	}
	return arm64RawUMLAL{
		highHalf:    highHalf,
		source:      arm64VectorArrangement{elementBits: sourceBits, lanes: sourceLanes},
		destination: arm64VectorArrangement{elementBits: sourceBits * 2, lanes: destinationLanes},
		destReg:     int(word & 31),
		first:       int(word>>5) & 31,
		second:      int(word>>16) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawUMLAL(form arm64RawUMLAL) error {
	op := Op("VUMLAL")
	if form.highHalf {
		op = "VUMLAL2"
	}
	sourceArrangement := arm64VectorArrangementName(form.source)
	destinationArrangement := arm64VectorArrangementName(form.destination)
	sourceReg := func(index int) Operand {
		return Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("V%d.%s", index, sourceArrangement))}
	}
	ins := Instr{
		Op:  op,
		Raw: fmt.Sprintf("decoded ARM64 WORD as %s", op),
		Args: []Operand{
			sourceReg(form.second),
			sourceReg(form.first),
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("V%d.%s", form.destReg, destinationArrangement))},
		},
	}
	ok, _, err := c.lowerARM64VectorWideningMultiply(op, ins)
	if !ok && err == nil {
		return fmt.Errorf("arm64 raw %s decoder reached no semantic lowerer", op)
	}
	return err
}
