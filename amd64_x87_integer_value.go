package plan9asm

import "fmt"

// Exact signed integers are a value representation, not a source permission
// or a remembered adjacent load. Every logical stack cell carries its payload
// through copies, pushes, pops, rotations and selections. Other writers clear
// the tag. The floating projection remains the existing binary64 model; this
// does not establish general extended-precision arithmetic or exception state.
type x87IntegerValue struct {
	floating string
	integer  string
	exact    string
}

func (c *amd64Ctx) loadX87IntegerValue(index int) x87IntegerValue {
	value := x87IntegerValue{floating: c.loadX87(index), integer: "0", exact: "false"}
	if c.x87ExactSlot[index] != "" {
		integer, exact := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s\n", integer, c.x87IntegerValueSlot[index])
		fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", exact, c.x87ExactSlot[index])
		value.integer, value.exact = "%"+integer, "%"+exact
	}
	return value
}

func (c *amd64Ctx) storeX87IntegerValue(index int, value x87IntegerValue) {
	c.storeX87(index, value.floating)
	if c.x87ExactSlot[index] != "" {
		fmt.Fprintf(c.b, "  store i64 %s, ptr %s\n", value.integer, c.x87IntegerValueSlot[index])
		fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", value.exact, c.x87ExactSlot[index])
	}
}

func (c *amd64Ctx) pushX87IntegerValue(value x87IntegerValue) error {
	for index := len(c.x87Slot) - 1; index > 0; index-- {
		c.storeX87IntegerValue(index, c.loadX87IntegerValue(index-1))
	}
	c.storeX87IntegerValue(0, value)
	return nil
}

func (c *amd64Ctx) lowerX87IntegerMove(form x86X87ValueForm) error {
	bits := int(form.memoryBytes() * 8)
	typ := amd64IntegerTypeForBits(bits)
	if form.push {
		integer, err := c.evalIntSized(form.source, typ)
		if err != nil {
			return err
		}
		if bits != 64 {
			wide := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sext %s %s to i64\n", wide, typ, integer)
			integer = "%" + wide
		}
		floating := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sitofp i64 %s to double\n", floating, integer)
		return c.pushX87IntegerValue(x87IntegerValue{"%" + floating, integer, "true"})
	}
	value := c.loadX87IntegerValue(0)
	var integer string
	if bits == 64 && c.useHardwareX87() {
		integer = c.convertX87ToI64Hardware()
	} else {
		rounded := c.roundX87Software(value.floating)
		converted := c.convertRoundedX87Integer(rounded, bits)
		exact := value.integer
		if bits < 64 {
			lower, upper := c.newTmp(), c.newTmp()
			valid, narrow, selected := c.newTmp(), c.newTmp(), c.newTmp()
			minimum := int64(-1) << uint(bits-1)
			fmt.Fprintf(c.b, "  %%%s = icmp sge i64 %s, %d\n", lower, exact, minimum)
			fmt.Fprintf(c.b, "  %%%s = icmp sle i64 %s, %d\n", upper, exact, -minimum-1)
			fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", valid, lower, upper)
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", narrow, exact, typ)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %%%s, %s %d\n", selected, valid, typ, narrow, typ, minimum)
			exact = "%" + selected
		}
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, %s %s, %s %s\n", selected, value.exact, typ, exact, typ, converted)
		integer = "%" + selected
	}
	if err := c.storeX87TypedMemory(form.destination, typ, integer); err != nil {
		return err
	}
	if form.spec.pop != 0 {
		c.popX87()
	}
	return nil
}
