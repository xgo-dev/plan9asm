package plan9asm

import "fmt"

type arm64RawFADDP struct {
	scalar      bool
	arrangement arm64VectorArrangement
	first       int
	second      int
	destination int
}

func decodeARM64RawFADDP(word uint32) (arm64RawFADDP, bool) {
	const vectorRegisters = uint32(31 | 31<<5 | 31<<16)
	var vectorArrangement arm64VectorArrangement
	switch word &^ vectorRegisters {
	case 0x2e401400:
		vectorArrangement = arm64VectorArrangement{elementBits: 16, lanes: 4}
	case 0x6e401400:
		vectorArrangement = arm64VectorArrangement{elementBits: 16, lanes: 8}
	case 0x2e20d400:
		vectorArrangement = arm64VectorArrangement{elementBits: 32, lanes: 2}
	case 0x6e20d400:
		vectorArrangement = arm64VectorArrangement{elementBits: 32, lanes: 4}
	case 0x6e60d400:
		vectorArrangement = arm64VectorArrangement{elementBits: 64, lanes: 2}
	}
	if vectorArrangement.elementBits != 0 {
		return arm64RawFADDP{
			arrangement: vectorArrangement,
			first:       int(word>>5) & 31,
			second:      int(word>>16) & 31,
			destination: int(word) & 31,
		}, true
	}

	const scalarRegisters = uint32(31 | 31<<5)
	scalarBits := 0
	switch word &^ scalarRegisters {
	case 0x5e30d800:
		scalarBits = 16
	case 0x7e30d800:
		scalarBits = 32
	case 0x7e70d800:
		scalarBits = 64
	}
	if scalarBits != 0 {
		return arm64RawFADDP{
			scalar:      true,
			arrangement: arm64VectorArrangement{elementBits: scalarBits, lanes: 2},
			first:       int(word>>5) & 31,
			second:      -1,
			destination: int(word) & 31,
		}, true
	}
	return arm64RawFADDP{}, false
}

func arm64RawFloatType(bits int) string {
	switch bits {
	case 16:
		return "half"
	case 32:
		return "float"
	case 64:
		return "double"
	default:
		panic(fmt.Sprintf("unsupported ARM64 floating width %d", bits))
	}
}

func (c *arm64Ctx) lowerRawFADDP(form arm64RawFADDP) error {
	firstReg := Reg(fmt.Sprintf("V%d", form.first))
	first, err := c.loadARM64VectorFloat(firstReg, form.arrangement)
	if err != nil {
		return err
	}
	floatType := arm64RawFloatType(form.arrangement.elementBits)
	if form.scalar {
		left := c.newTmp()
		right := c.newTmp()
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <2 x %s> %s, i32 0\n", left, floatType, first)
		fmt.Fprintf(c.b, "  %%%s = extractelement <2 x %s> %s, i32 1\n", right, floatType, first)
		fmt.Fprintf(c.b, "  %%%s = fadd %s %%%s, %%%s\n", result, floatType, left, right)
		return c.storeARM64ScalarFloatReg(Reg(fmt.Sprintf("F%d", form.destination)), form.arrangement.elementBits, "%"+result)
	}

	second, err := c.loadARM64VectorFloat(Reg(fmt.Sprintf("V%d", form.second)), form.arrangement)
	if err != nil {
		return err
	}
	result := "poison"
	half := form.arrangement.lanes / 2
	for lane := 0; lane < form.arrangement.lanes; lane++ {
		source := first
		if lane >= half {
			source = second
		}
		pair := (lane % half) * 2
		left := c.newTmp()
		right := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x %s> %s, i32 %d\n", left, form.arrangement.lanes, floatType, source, pair)
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x %s> %s, i32 %d\n", right, form.arrangement.lanes, floatType, source, pair+1)
		combined := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fadd %s %%%s, %%%s\n", combined, floatType, left, right)
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x %s> %s, %s %%%s, i32 %d\n",
			inserted, form.arrangement.lanes, floatType, result, floatType, combined, lane)
		result = "%" + inserted
	}
	return c.storeARM64VectorFloat(Reg(fmt.Sprintf("V%d", form.destination)), form.arrangement, result)
}
