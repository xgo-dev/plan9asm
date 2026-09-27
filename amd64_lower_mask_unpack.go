package plan9asm

import "fmt"

// amd64MaskUnpackBits covers Go 1.27's complete KUNPCK family. The Plan 9
// first source is the encoded r/m operand and becomes the low half; the second
// source is VEX.vvvv and becomes the high half of the destination mask.
var amd64MaskUnpackBits = map[Op]int{
	"KUNPCKBW": 8,
	"KUNPCKWD": 16,
	"KUNPCKDQ": 32,
}

func (c *amd64Ctx) lowerMaskUnpack(op Op, ins Instr) error {
	bits := amd64MaskUnpackBits[op]
	if len(ins.Args) != 3 {
		return fmt.Errorf("%s %s expects three K-register operands: %q", c.goarch, op, ins.Raw)
	}
	for _, arg := range ins.Args {
		if !amd64IsKOperand(arg) {
			return fmt.Errorf("%s %s expects only K0..K7 operands: %q", c.goarch, op, ins.Raw)
		}
	}

	low, err := c.loadK(ins.Args[0].Reg)
	if err != nil {
		return err
	}
	high, err := c.loadK(ins.Args[1].Reg)
	if err != nil {
		return err
	}
	low = c.maskMoveI64(low, bits)
	high = c.maskMoveI64(high, bits)
	shifted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shl i64 %s, %d\n", shifted, high, bits)
	combined := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %s\n", combined, shifted, low)
	result := "%" + combined
	if bits < 32 {
		result = c.maskMoveI64(result, bits*2)
	}
	return c.storeK(ins.Args[2].Reg, result)
}
