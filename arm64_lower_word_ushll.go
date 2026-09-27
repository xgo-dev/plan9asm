package plan9asm

import "fmt"

type arm64RawUSHLL struct {
	highHalf               bool
	shift                  int
	sourceArrangement      arm64VectorArrangement
	destinationArrangement arm64VectorArrangement
	source                 int
	destination            int
}

func decodeARM64RawUSHLL(word uint32) (arm64RawUSHLL, bool) {
	if word&0xbf80fc00 != 0x2f00a400 {
		return arm64RawUSHLL{}, false
	}
	encodedImmediate := int(word>>16) & 0x7f
	bits := 0
	switch {
	case encodedImmediate >= 32 && encodedImmediate < 64:
		bits = 32
	case encodedImmediate >= 16:
		bits = 16
	case encodedImmediate >= 8:
		bits = 8
	default:
		return arm64RawUSHLL{}, false
	}
	shift := encodedImmediate - bits
	destinationLanes := 128 / (bits * 2)
	highHalf := word&(1<<30) != 0
	sourceLanes := destinationLanes
	if highHalf {
		sourceLanes *= 2
	}
	return arm64RawUSHLL{
		highHalf:               highHalf,
		shift:                  shift,
		sourceArrangement:      arm64VectorArrangement{elementBits: bits, lanes: sourceLanes},
		destinationArrangement: arm64VectorArrangement{elementBits: bits * 2, lanes: destinationLanes},
		source:                 int(word>>5) & 31,
		destination:            int(word & 31),
	}, true
}

func (c *arm64Ctx) lowerRawUSHLL(form arm64RawUSHLL) error {
	op := Op("VUSHLL")
	if form.highHalf {
		op = "VUSHLL2"
	}
	ins := Instr{
		Op:  op,
		Raw: fmt.Sprintf("decoded ARM64 WORD as %s", op),
		Args: []Operand{
			{Kind: OpImm, Imm: int64(form.shift)},
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("V%d.%s", form.source, arm64VectorArrangementName(form.sourceArrangement)))},
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("V%d.%s", form.destination, arm64VectorArrangementName(form.destinationArrangement)))},
		},
	}
	ok, _, err := c.lowerARM64WideningShift(op, ins)
	if !ok && err == nil {
		return fmt.Errorf("arm64 raw %s decoder reached no semantic lowerer", op)
	}
	return err
}
