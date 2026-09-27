package plan9asm

import (
	"fmt"
	"strings"
)

// lowerScalarADCSBB implements every operand row in Go 1.27's yxorb (B)
// and yaddl (W/L/Q) tables for add-with-carry and subtract-with-borrow.
func (c *amd64Ctx) lowerScalarADCSBB(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	add, bits, recognized := amd64ScalarADCSBBProperties(baseOp)
	if !recognized {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	if c.goarch == "386" && bits == 64 {
		return true, false, fmt.Errorf("386 %s is illegal in 32-bit mode: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 2 {
		return true, false, fmt.Errorf("%s %s expects source and destination: %q", c.goarch, baseOp, ins.Raw)
	}
	if err := validateAMD64ScalarAddSubOperands(c.goarch, baseOp, bits, ins.Args[0], ins.Args[1], ins); err != nil {
		return true, false, err
	}

	source, destination := ins.Args[0], ins.Args[1]
	typ := amd64IntegerTypeForBits(bits)
	var sourceValue string
	if source.Kind == OpImm {
		sourceValue = amd64ScalarAddSubImmediate(source.Imm, bits)
	} else {
		sourceValue, err = c.evalIntSized(source, typ)
		if err != nil {
			return true, false, err
		}
	}
	destinationValue, store, err := c.loadIntDestination(destination, typ)
	if err != nil {
		return true, false, err
	}

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
		return true, false, err
	}
	c.setScalarADCSBBFlags(typ, add, destinationValue, sourceValue, resultValue, "%"+carryOut)
	return true, false, nil
}

func amd64ScalarADCSBBProperties(op string) (add bool, bits int, ok bool) {
	switch op {
	case "ADCB":
		return true, 8, true
	case "ADCW":
		return true, 16, true
	case "ADCL":
		return true, 32, true
	case "ADCQ":
		return true, 64, true
	case "SBBB":
		return false, 8, true
	case "SBBW":
		return false, 16, true
	case "SBBL":
		return false, 32, true
	case "SBBQ":
		return false, 64, true
	default:
		return false, 0, false
	}
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

func (c *amd64Ctx) setScalarADCSBBFlags(typ LLVMType, add bool, destination, source, result, carry string) {
	fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", carry, c.flagsCFSlot)

	xorOperands := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", xorOperands, typ, destination, source)
	overflowInput := "%" + xorOperands
	if add {
		inverted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, -1\n", inverted, typ, overflowInput)
		overflowInput = "%" + inverted
	}
	xorResult := c.newTmp()
	overflowBits := c.newTmp()
	overflow := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", xorResult, typ, destination, result)
	fmt.Fprintf(c.b, "  %%%s = and %s %s, %%%s\n", overflowBits, typ, overflowInput, xorResult)
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %%%s, 0\n", overflow, typ, overflowBits)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", overflow, c.flagsOFSlot)

	zero := c.newTmp()
	sign := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, 0\n", zero, typ, result)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zero, c.flagsZSlot)
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, 0\n", sign, typ, result)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", sign, c.flagsSltSlot)
	c.setParityFlagSized(typ, result)
}
