package plan9asm

import "fmt"

func (c *amd64Ctx) emitScalarADCSBB(spec x86LockScalarRMWSpec, typ LLVMType, destinationValue, sourceValue string,
	store func(string) error) error {
	add, bits := spec.stem == "ADC", spec.bits
	wideType := LLVMType(fmt.Sprintf("i%d", bits*2))
	widen := func(value string) string {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", wide, typ, value, wideType)
		return "%" + wide
	}
	wideDestination := widen(destinationValue)
	wideSource := widen(sourceValue)
	carry := c.loadFlag(c.flagsCFSlot)
	wideCarryName := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i1 %s to %s\n", wideCarryName, carry, wideType)
	wideCarry := "%" + wideCarryName

	partial := c.newTmp()
	wideResult := c.newTmp()
	var carryOut string
	if add {
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", partial, wideType, wideDestination, wideSource)
		fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %s\n", wideResult, wideType, partial, wideCarry)
		carryOut = c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ugt %s %%%s, %s\n", carryOut, wideType, wideResult, amd64UnsignedMaximum(bits))
	} else {
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", partial, wideType, wideSource, wideCarry)
		fmt.Fprintf(c.b, "  %%%s = sub %s %s, %%%s\n", wideResult, wideType, wideDestination, partial)
		carryOut = c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ult %s %s, %%%s\n", carryOut, wideType, wideDestination, partial)
	}

	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", result, wideType, wideResult, typ)
	resultValue := "%" + result
	if err := store(resultValue); err != nil {
		return err
	}
	c.setScalarAddSubCarryFlags(typ, add, destinationValue, sourceValue, resultValue, "%"+carryOut)
	return nil
}

func amd64UnsignedMaximum(bits int) string {
	switch bits {
	case 8:
		return "255"
	case 16:
		return "65535"
	case 32:
		return "4294967295"
	case 64:
		return "18446744073709551615"
	default:
		panic(fmt.Sprintf("unsupported x86 integer width %d", bits))
	}
}
