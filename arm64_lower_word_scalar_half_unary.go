package plan9asm

import "fmt"

type arm64RawScalarHalfUnary struct {
	operation   string
	source      int
	destination int
}

// Go 1.27 has named FABS/FNEG/FSQRT/FRINT scalar forms for S and D, but
// no H optab forms. The full FP16 scalar unary encoding family therefore
// reaches us as WORD directives.
func decodeARM64RawScalarHalfUnary(word uint32) (arm64RawScalarHalfUnary, bool) {
	const registers = uint32(31 | 31<<5)
	operations := map[uint32]string{
		0x1ee0c000: "fabs",
		0x1ee14000: "neg",
		0x1ee1c000: "sqrt",
		0x1ee64000: "round",
		0x1ee7c000: "nearbyint",
		0x1ee54000: "floor",
		0x1ee44000: "roundeven",
		0x1ee4c000: "ceil",
		0x1ee74000: "rint",
		0x1ee5c000: "trunc",
	}
	operation, ok := operations[word&^registers]
	if !ok {
		return arm64RawScalarHalfUnary{}, false
	}
	return arm64RawScalarHalfUnary{
		operation:   operation,
		source:      int(word>>5) & 31,
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawScalarHalfUnary(form arm64RawScalarHalfUnary) error {
	sourceReg := Reg(fmt.Sprintf("F%d", form.source))
	destinationReg := Reg(fmt.Sprintf("F%d", form.destination))
	source, err := c.loadARM64ScalarFloatReg(sourceReg, 16)
	if err != nil {
		return err
	}
	result := c.newTmp()
	if form.operation == "neg" {
		fmt.Fprintf(c.b, "  %%%s = fneg half %s\n", result, source)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call half @llvm.%s.f16(half %s)\n", result, form.operation, source)
	}
	return c.storeARM64ScalarFloatReg(destinationReg, 16, "%"+result)
}
