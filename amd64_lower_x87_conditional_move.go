package plan9asm

import "fmt"

func (c *amd64Ctx) lowerX87ConditionalMove(op Op, ins Instr) error {
	if len(ins.Args) != 2 {
		return fmt.Errorf("%s %s expects one x87 source and F0 destination: %q", c.goarch, op, ins.Raw)
	}
	source, sourceOK := x87OperandReg(ins.Args[0])
	destination, destinationOK := x87OperandReg(ins.Args[1])
	if !sourceOK || !destinationOK || destination != 0 {
		return fmt.Errorf("%s %s operands are outside Go 1.27's Yrf,F0 row: %q", c.goarch, op, ins.Raw)
	}

	cf := func() string { return c.loadFlag(c.flagsCFSlot) }
	zf := func() string { return c.loadFlag(c.flagsZSlot) }
	pf := func() string { return c.loadFlag(c.flagsPFSlot) }
	not := func(value string) string {
		inverted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %s, true\n", inverted, value)
		return "%" + inverted
	}
	combine := func(instruction, left, right string) string {
		condition := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s i1 %s, %s\n", condition, instruction, left, right)
		return "%" + condition
	}

	condition := ""
	switch op {
	case "FCMOVB", "FCMOVCS":
		condition = cf()
	case "FCMOVBE", "FCMOVLS":
		condition = combine("or", cf(), zf())
	case "FCMOVE", "FCMOVEQ":
		condition = zf()
	case "FCMOVNB", "FCMOVCC":
		condition = not(cf())
	case "FCMOVNBE", "FCMOVHI":
		condition = combine("and", not(cf()), not(zf()))
	case "FCMOVNE":
		condition = not(zf())
	case "FCMOVNU":
		condition = not(pf())
	case "FCMOVU", "FCMOVUN":
		condition = pf()
	default:
		return fmt.Errorf("unsupported x87 conditional move %s", op)
	}
	sourceValue := c.loadX87IntegerValue(source)
	destinationValue := c.loadX87IntegerValue(0)
	selected := c.newTmp()
	integer, exact := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, double %s, double %s\n", selected, condition, sourceValue.floating, destinationValue.floating)
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i64 %s, i64 %s\n", integer, condition, sourceValue.integer, destinationValue.integer)
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i1 %s, i1 %s\n", exact, condition, sourceValue.exact, destinationValue.exact)
	c.storeX87IntegerValue(0, x87IntegerValue{"%" + selected, "%" + integer, "%" + exact})
	return nil
}
