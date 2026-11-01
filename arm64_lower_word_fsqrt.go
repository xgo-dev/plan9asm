package plan9asm

import "fmt"

type arm64RawFSQRT struct {
	arrangement arm64VectorArrangement
	source      int
	destination int
}

func decodeARM64RawFSQRT(word uint32) (arm64RawFSQRT, bool) {
	const registers = uint32(31 | 31<<5)
	if key := word &^ registers; key == 0x2ef9f800 || key == 0x6ef9f800 {
		lanes := 4
		if word&(1<<30) != 0 {
			lanes = 8
		}
		return arm64RawFSQRT{
			arrangement: arm64VectorArrangement{elementBits: 16, lanes: lanes},
			source:      int(word>>5) & 31,
			destination: int(word) & 31,
		}, true
	}
	if word&0xbfbffc00 != 0x2ea1f800 { // Ignore Q, size, Rn, and Rd.
		return arm64RawFSQRT{}, false
	}
	elementBits := 32
	if word&(1<<22) != 0 {
		elementBits = 64
	}
	vectorBits := 64
	if word&(1<<30) != 0 {
		vectorBits = 128
	}
	if elementBits == 64 && vectorBits == 64 {
		return arm64RawFSQRT{}, false
	}
	return arm64RawFSQRT{
		arrangement: arm64VectorArrangement{elementBits: elementBits, lanes: vectorBits / elementBits},
		source:      int(word>>5) & 31,
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawFSQRT(form arm64RawFSQRT) error {
	if form.arrangement.elementBits == 16 {
		source, err := c.loadARM64VectorFloat(Reg(fmt.Sprintf("V%d", form.source)), form.arrangement)
		if err != nil {
			return err
		}
		result := c.newTmp()
		vectorType := fmt.Sprintf("<%d x half>", form.arrangement.lanes)
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.sqrt.v%df16(%s %s)\n", result, vectorType, form.arrangement.lanes, vectorType, source)
		return c.storeARM64VectorFloat(Reg(fmt.Sprintf("V%d", form.destination)), form.arrangement, "%"+result)
	}
	arrangement := arm64VectorArrangementName(form.arrangement)
	ins := Instr{
		Op:  "VFSQRT",
		Raw: "decoded ARM64 WORD as VFSQRT",
		Args: []Operand{
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("V%d.%s", form.source, arrangement))},
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("V%d.%s", form.destination, arrangement))},
		},
	}
	ok, _, err := c.lowerARM64VectorFloatUnary("VFSQRT", ins)
	if !ok && err == nil {
		return fmt.Errorf("arm64 raw VFSQRT decoder reached no semantic lowerer")
	}
	return err
}
