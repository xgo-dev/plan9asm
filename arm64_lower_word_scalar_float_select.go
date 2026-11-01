package plan9asm

import "fmt"

type arm64RawScalarFloatSelect struct {
	bits        int
	condition   int
	first       int
	second      int
	destination int
}

var arm64RawScalarFloatSelectWidths = map[uint32]int{
	0x1ee00c00: 16,
	0x1e200c00: 32,
	0x1e600c00: 64,
}

var arm64RawConditionNames = [...]string{
	"EQ", "NE", "HS", "LO",
	"MI", "PL", "VS", "VC",
	"HI", "LS", "GE", "LT",
	"GT", "LE", "AL", "NV",
}

func decodeARM64RawScalarFloatSelect(word uint32) (arm64RawScalarFloatSelect, bool) {
	const operands = uint32(31 | 31<<5 | 15<<12 | 31<<16)
	bits, ok := arm64RawScalarFloatSelectWidths[word&^operands]
	if !ok {
		return arm64RawScalarFloatSelect{}, false
	}
	return arm64RawScalarFloatSelect{
		bits:        bits,
		condition:   int(word>>12) & 15,
		first:       int(word>>5) & 31,
		second:      int(word>>16) & 31,
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawScalarFloatSelect(form arm64RawScalarFloatSelect) error {
	return c.lowerARM64FloatSelectValues(
		form.bits,
		arm64RawConditionNames[form.condition],
		Reg(fmt.Sprintf("F%d", form.first)),
		Reg(fmt.Sprintf("F%d", form.second)),
		Reg(fmt.Sprintf("F%d", form.destination)),
	)
}

func (c *arm64Ctx) lowerARM64FloatSelectValues(bits int, condition string, firstReg, secondReg, destination Reg) error {
	first, err := c.loadARM64ScalarFloatReg(firstReg, bits)
	if err != nil {
		return err
	}
	second, err := c.loadARM64ScalarFloatReg(secondReg, bits)
	if err != nil {
		return err
	}
	predicate, err := c.condValue(condition)
	if err != nil {
		return err
	}
	typeName := "half"
	if bits == 32 {
		typeName = "float"
	} else if bits == 64 {
		typeName = "double"
	}
	selected := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, %s %s, %s %s\n", selected, predicate, typeName, first, typeName, second)
	return c.storeARM64ScalarFloatReg(destination, bits, "%"+selected)
}
