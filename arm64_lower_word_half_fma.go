package plan9asm

import "fmt"

// The named Go FMA forms cover S and D operands. Go source can also contain
// raw half-precision encodings; each has four independent five-bit registers.
type arm64RawHalfFMA struct {
	op          string
	destination int
	first       int
	addend      int
	second      int
}

var arm64RawHalfFMABases = map[uint32]string{
	0x1fc00000: "FMADD",
	0x1fc08000: "FMSUB",
	0x1fe00000: "FNMADD",
	0x1fe08000: "FNMSUB",
}

func decodeARM64RawHalfFMA(word uint32) (arm64RawHalfFMA, bool) {
	const registers = uint32(31 | 31<<5 | 31<<10 | 31<<16)
	op, ok := arm64RawHalfFMABases[word&^registers]
	if !ok {
		return arm64RawHalfFMA{}, false
	}
	return arm64RawHalfFMA{
		op:          op,
		destination: int(word) & 31,
		first:       int(word>>5) & 31,
		addend:      int(word>>10) & 31,
		second:      int(word>>16) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawHalfFMA(form arm64RawHalfFMA) error {
	load := func(register int) (string, error) {
		return c.loadARM64ScalarFloatReg(Reg(fmt.Sprintf("F%d", register)), 16)
	}
	first, err := load(form.first)
	if err != nil {
		return err
	}
	second, err := load(form.second)
	if err != nil {
		return err
	}
	addend, err := load(form.addend)
	if err != nil {
		return err
	}

	if form.op == "FMSUB" {
		negated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fneg half %s\n", negated, first)
		first = "%" + negated
	} else if form.op == "FNMSUB" {
		negated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fneg half %s\n", negated, addend)
		addend = "%" + negated
	}

	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call half @llvm.fma.f16(half %s, half %s, half %s)\n",
		result, first, second, addend)
	value := "%" + result
	if form.op == "FNMADD" {
		negated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fneg half %s\n", negated, value)
		value = "%" + negated
	}
	return c.storeARM64ScalarFloatReg(Reg(fmt.Sprintf("F%d", form.destination)), 16, value)
}
