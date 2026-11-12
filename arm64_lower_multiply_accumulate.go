package plan9asm

import "fmt"

type arm64MultiplyAccumulateSpec struct {
	word, long, signed, subtract bool
}

// The complete Go AMADD row: four C_ZREG operands in Rm, Ra, Rn, Rd order.
var arm64MultiplyAccumulateOps = map[Op]arm64MultiplyAccumulateSpec{
	"MADD":   {},
	"MSUB":   {subtract: true},
	"MADDW":  {word: true},
	"MSUBW":  {word: true, subtract: true},
	"SMADDL": {long: true, signed: true},
	"SMSUBL": {long: true, signed: true, subtract: true},
	"UMADDL": {long: true},
	"UMSUBL": {long: true, subtract: true},
}

func (c *arm64Ctx) lowerARM64MultiplyAccumulate(spec arm64MultiplyAccumulateSpec, ins Instr) error {
	// Read all inputs before writing Rd: it may alias any source. In Go
	// syntax the middle source is the addend, not the second multiplicand.
	if spec.long {
		return c.lowerARM64MultiplyAddLong(spec.signed, spec.subtract,
			ins.Args[0], ins.Args[2], ins.Args[1], ins.Args[3].Reg)
	}
	evaluate := func(operand Operand) (string, error) {
		if spec.word {
			return c.eval32(operand)
		}
		return c.eval64(operand, false)
	}
	m, err := evaluate(ins.Args[0])
	if err != nil {
		return err
	}
	a, err := evaluate(ins.Args[1])
	if err != nil {
		return err
	}
	n, err := evaluate(ins.Args[2])
	if err != nil {
		return err
	}
	width := "i64"
	if spec.word {
		width = "i32"
	}
	operation := "add"
	if spec.subtract {
		operation = "sub"
	}
	product, result := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = mul %s %s, %s\n", product, width, m, n)
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %%%s\n", result, operation, width, a, product)
	if spec.word {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", wide, result)
		result = wide
	}
	return c.storeReg(ins.Args[3].Reg, "%"+result)
}
