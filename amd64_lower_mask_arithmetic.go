package plan9asm

import "fmt"

type amd64MaskArithmeticSpec struct {
	bits  int
	shift string
}

// amd64MaskArithmeticSpecs covers Go 1.27's complete KADD and KSHIFT
// families. KADD wraps at the named mask width; KSHIFT produces zero when the
// unsigned byte count is greater than or equal to that width.
var amd64MaskArithmeticSpecs = map[Op]amd64MaskArithmeticSpec{
	"KADDB": {bits: 8}, "KADDW": {bits: 16}, "KADDD": {bits: 32}, "KADDQ": {bits: 64},
	"KSHIFTLB": {bits: 8, shift: "shl"}, "KSHIFTLW": {bits: 16, shift: "shl"},
	"KSHIFTLD": {bits: 32, shift: "shl"}, "KSHIFTLQ": {bits: 64, shift: "shl"},
	"KSHIFTRB": {bits: 8, shift: "lshr"}, "KSHIFTRW": {bits: 16, shift: "lshr"},
	"KSHIFTRD": {bits: 32, shift: "lshr"}, "KSHIFTRQ": {bits: 64, shift: "lshr"},
}

func (c *amd64Ctx) lowerMaskArithmetic(op Op, ins Instr) error {
	spec := amd64MaskArithmeticSpecs[op]
	if spec.shift == "" {
		if len(ins.Args) != 3 {
			return fmt.Errorf("%s %s expects three K-register operands: %q", c.goarch, op, ins.Raw)
		}
		for _, arg := range ins.Args {
			if !amd64IsKOperand(arg) {
				return fmt.Errorf("%s %s expects only K0..K7 operands: %q", c.goarch, op, ins.Raw)
			}
		}
		first, err := c.loadK(ins.Args[0].Reg)
		if err != nil {
			return err
		}
		second, err := c.loadK(ins.Args[1].Reg)
		if err != nil {
			return err
		}
		first = c.maskMoveI64(first, spec.bits)
		second = c.maskMoveI64(second, spec.bits)
		added := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", added, first, second)
		return c.storeK(ins.Args[2].Reg, c.maskMoveI64("%"+added, spec.bits))
	}

	if len(ins.Args) != 3 || !amd64UnsignedImmediate(ins.Args[0], 8) || !amd64IsKOperand(ins.Args[1]) || !amd64IsKOperand(ins.Args[2]) {
		return fmt.Errorf("%s %s expects $u8, K0..K7, K0..K7: %q", c.goarch, op, ins.Raw)
	}
	source, err := c.loadK(ins.Args[1].Reg)
	if err != nil {
		return err
	}
	source = c.maskMoveI64(source, spec.bits)
	result := "0"
	count := int(uint8(ins.Args[0].Imm))
	if count < spec.bits {
		shifted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s i64 %s, %d\n", shifted, spec.shift, source, count)
		result = c.maskMoveI64("%"+shifted, spec.bits)
	}
	return c.storeK(ins.Args[2].Reg, result)
}
