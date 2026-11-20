package plan9asm

import "fmt"

type arm64RawVectorFloatRound struct {
	operation   string
	arrangement arm64VectorArrangement
	source      int
	destination int
}

func decodeARM64RawVectorFloatRound(word uint32) (arm64RawVectorFloatRound, bool) {
	operation := ""
	switch word & 0xbfbffc00 {
	case 0x2e218800:
		operation = "round"
	case 0x2e219800:
		operation = "rint"
	case 0x2ea19800:
		operation = "nearbyint"
	default:
		return arm64RawVectorFloatRound{}, false
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
		return arm64RawVectorFloatRound{}, false
	}
	return arm64RawVectorFloatRound{
		operation:   operation,
		arrangement: arm64VectorArrangement{elementBits: elementBits, lanes: vectorBits / elementBits},
		source:      int(word>>5) & 31,
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawVectorFloatRound(form arm64RawVectorFloatRound) error {
	arrangementName := arm64VectorArrangementName(form.arrangement)
	sourceReg := Reg(fmt.Sprintf("V%d.%s", form.source, arrangementName))
	destinationReg := Reg(fmt.Sprintf("V%d.%s", form.destination, arrangementName))
	source, err := c.loadARM64VectorFloat(sourceReg, form.arrangement)
	if err != nil {
		return err
	}
	floatType := "float"
	suffix := fmt.Sprintf("v%df32", form.arrangement.lanes)
	if form.arrangement.elementBits == 64 {
		floatType = "double"
		suffix = fmt.Sprintf("v%df64", form.arrangement.lanes)
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <%d x %s> @llvm.%s.%s(<%d x %s> %s)\n",
		result, form.arrangement.lanes, floatType, form.operation, suffix,
		form.arrangement.lanes, floatType, source)
	return c.storeARM64VectorFloat(destinationReg, form.arrangement, "%"+result)
}
