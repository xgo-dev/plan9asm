package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) loadX87Operand(source Operand, width byte) (x87Value, error) {
	if index, register := x87OperandReg(source); register {
		return c.loadX87Value(index), nil
	}
	if width == 'B' || width == 'X' {
		if !c.x87NativeValues {
			return "", fmt.Errorf("%w: x87 encoded portable memory needs its exact codec", ErrProbeNeedsContext)
		}
		return c.loadX87NativeEncoded(source, width)
	}
	if width == 'F' || width == 'D' {
		bits := 64
		if width == 'F' {
			bits = 32
		}
		value, err := c.loadX87FloatingMove(source, bits)
		if err != nil {
			return "", err
		}
		if c.x87NativeValues {
			return c.x87NativeFromFloat(value, bits), nil
		}
		return c.x87PortableFromFloat(value, bits)
	}
	bits := 16
	if width == 'L' {
		bits = 32
	} else if width == 'V' {
		bits = 64
	} else if width != 'W' {
		return "", fmt.Errorf("unsupported typed x87 scalar width %c", width)
	}
	value, err := c.loadStackValue(source, bits)
	if err != nil {
		return "", err
	}
	if c.x87NativeValues {
		return c.x87NativeFromSigned(value, bits), nil
	}
	return c.x87PortableFromSigned(value, bits)
}

func (c *amd64Ctx) x87LogicalControlWord() string {
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i16, ptr %s\n", value, c.x87ControlSlot)
	return "%" + value
}

func (c *amd64Ctx) storeX87Operand(destination Operand, value x87Value, width byte) error {
	if index, register := x87OperandReg(destination); register {
		c.storeX87Value(index, value)
		return nil
	}
	if width == 'B' || width == 'X' {
		if !c.x87NativeValues {
			return fmt.Errorf("%w: x87 encoded portable memory needs its exact codec", ErrProbeNeedsContext)
		}
		return c.storeX87NativeEncoded(destination, value, width)
	}
	bits := 64
	if width == 'F' {
		bits = 32
	}
	if width == 'F' || width == 'D' {
		typ := LLVMType("double")
		if bits == 32 {
			typ = LLVMType("float")
		}
		var floating string
		if c.x87NativeValues {
			floating = c.x87NativeToFloat(value, bits)
		} else {
			var err error
			floating, err = c.x87PortableToFloat(value, bits, c.x87LogicalControlWord())
			if err != nil {
				return err
			}
		}
		return c.storeX87TypedMemory(destination, typ, floating)
	}
	if width == 'W' {
		bits = 16
	} else if width == 'L' {
		bits = 32
	} else if width != 'V' {
		return fmt.Errorf("unsupported typed x87 scalar store width %c", width)
	}
	var integer string
	if c.x87NativeValues {
		integer = c.x87NativeToSigned(value, bits)
	} else {
		var err error
		integer, err = c.x87PortableToSigned(value, bits, c.x87LogicalControlWord())
		if err != nil {
			return err
		}
	}
	return c.storeX87TypedMemory(destination, amd64IntegerTypeForBits(bits), integer)
}

// This is a backend for the existing typed forms, not a second source grammar.
// Source availability, exact raw replay and conditional memory roles are still
// checked before lowering. No native C long-double ABI is involved.
func (c *amd64Ctx) lowerX87Value(op Op, ins Instr, form x86X87ValueForm, typed bool) (bool, error) {
	if !typed && len(ins.Args) != 0 {
		return false, nil // The existing non-value grammar reports the error.
	}
	if typed {
		switch form.spec.kind {
		case x86X87FloatMove, x86X87IntegerMove:
			if form.push {
				value, err := c.loadX87Operand(form.source, form.spec.width)
				if err != nil {
					return true, err
				}
				return true, c.pushX87Value(value)
			}
			index, register := x87OperandReg(form.source)
			if !register {
				return true, fmt.Errorf("%s lacks a typed x87 value source", op)
			}
			if err := c.storeX87Operand(form.destination, c.loadX87Value(index), form.spec.width); err != nil {
				return true, err
			}
			for count := uint8(0); count < form.spec.pop; count++ {
				c.popX87Value()
			}
			return true, nil
		case x86X87Arithmetic:
			source, err := c.loadX87Operand(ins.Args[0], form.spec.width)
			if err != nil {
				return true, err
			}
			destination, register := x87OperandReg(ins.Args[1])
			if !register {
				return true, fmt.Errorf("%s lacks a typed x87 accumulator", op)
			}
			left, right := c.loadX87Value(destination), source
			if form.spec.reverse {
				left, right = right, left
			}
			instruction := strings.ToLower(strings.TrimSuffix(string(form.spec.stem), "R"))
			var result x87Value
			if c.x87NativeValues {
				result, _, _ = c.evaluateX87Native(instruction+" %st(1), %st(0)", []x87Value{left, right}, 1, 2)
			} else {
				var err error
				result, err = c.x87PortableBinary(instruction, left, right, c.x87LogicalControlWord())
				if err != nil {
					return true, err
				}
			}
			c.storeX87Value(destination, result)
			if form.spec.pop != 0 {
				c.popX87Value()
			}
			return true, nil
		case x86X87Compare:
			left, err := c.loadX87Operand(form.left, 'D')
			if err != nil {
				return true, err
			}
			right, err := c.loadX87Operand(form.right, form.spec.width)
			if err != nil {
				return true, err
			}
			var status string
			if c.x87NativeValues {
				instruction := "fcom"
				if strings.HasPrefix(string(op), "FUCOM") {
					instruction = "fucom"
				}
				_, _, status = c.evaluateX87Native(instruction+" %st(1)", []x87Value{left, right}, 0, 2)
			} else {
				status = c.x87PortableCompareStatus(left, right)
			}
			if form.spec.directFlags {
				c.setX87CompareFlags(status)
			} else {
				c.projectX87Status(status, 0x4700)
			}
			for count := uint8(0); count < form.spec.pop; count++ {
				c.popX87Value()
			}
			return true, nil
		}
	}
	if strings.HasPrefix(string(op), "FCMOV") {
		return true, c.lowerX87ConditionalMove(op, ins)
	}
	switch op {
	case "FXCHD":
		left, _ := x87OperandReg(ins.Args[0])
		right, _ := x87OperandReg(ins.Args[1])
		a, b := c.loadX87Value(left), c.loadX87Value(right)
		c.storeX87Value(left, b)
		c.storeX87Value(right, a)
	case "FLDZ", "FLD1", "FLDPI", "FLDL2E", "FLDL2T", "FLDLG2", "FLDLN2":
		var value x87Value
		if c.x87NativeValues {
			value, _, _ = c.evaluateX87Native(strings.ToLower(string(op)), nil, 1, 1)
		} else {
			var err error
			value, err = c.x87PortableConstant(op, c.x87LogicalControlWord())
			if err != nil {
				return true, err
			}
		}
		return true, c.pushX87Value(value)
	case "FABS", "FCHS", "FSQRT", "FRNDINT", "F2XM1", "FSIN", "FCOS":
		if !c.x87NativeValues {
			if op != "FABS" && op != "FCHS" && op != "FRNDINT" && op != "FSQRT" {
				return false, nil // The remaining mathematical provider is separate.
			}
			value, err := c.x87PortableUnary(op, c.loadX87Value(0), c.x87LogicalControlWord())
			if err == nil {
				c.storeX87Value(0, value)
			}
			return true, err
		}
		value, _, status := c.evaluateX87Native(strings.ToLower(string(op)), []x87Value{c.loadX87Value(0)}, 1, 1)
		c.storeX87Value(0, value)
		if op == "FSIN" || op == "FCOS" {
			c.projectX87Status(status, 0x0400)
		}
	case "FPTAN", "FSINCOS", "FXTRACT":
		if !c.x87NativeValues {
			return false, nil
		}
		var before [8]x87Value
		if op != "FXTRACT" {
			for index := range before {
				before[index] = c.loadX87Value(index)
			}
		}
		first, second, status := c.evaluateX87Native(strings.ToLower(string(op)), []x87Value{c.loadX87Value(0)}, 2, 2)
		c.storeX87Value(0, second)
		if err := c.pushX87Value(first); err != nil {
			return true, err
		}
		if op != "FXTRACT" {
			masked, outOfRange := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i16 %s, 1024\n", masked, status)
			fmt.Fprintf(c.b, "  %%%s = icmp ne i16 %%%s, 0\n", outOfRange, masked)
			for index, original := range before {
				selected := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %s, %s %s\n", selected, outOfRange, x87ValueType, original, x87ValueType, c.loadX87Value(index))
				c.storeX87Value(index, x87Value("%"+selected))
			}
			c.projectX87Status(status, 0x0400)
		}
	case "FPATAN", "FYL2X", "FYL2XP1", "FSCALE", "FPREM", "FPREM1":
		if !c.x87NativeValues {
			return false, nil
		}
		remaining := 2
		pop := op == "FPATAN" || op == "FYL2X" || op == "FYL2XP1"
		if pop {
			remaining = 1
		}
		result, _, status := c.evaluateX87Native(strings.ToLower(string(op)), []x87Value{c.loadX87Value(0), c.loadX87Value(1)}, 1, remaining)
		if pop {
			c.storeX87Value(1, result)
			c.popX87Value()
		} else {
			c.storeX87Value(0, result)
		}
		if op == "FPREM" || op == "FPREM1" {
			c.projectX87Status(status, 0x4700)
		}
	case "FTST", "FXAM":
		var status string
		if c.x87NativeValues {
			_, _, status = c.evaluateX87Native(strings.ToLower(string(op)), []x87Value{c.loadX87Value(0)}, 0, 1)
		} else if op == "FTST" {
			status = c.x87PortableCompareStatus(c.loadX87Value(0), x87ZeroValue)
		} else {
			status = c.x87PortableClassify(c.loadX87Value(0))
		}
		c.projectX87Status(status, 0x4700)
	case "FDECSTP", "FINCSTP":
		c.rotateX87Values(op == "FINCSTP")
	default:
		return false, nil
	}
	return true, nil
}

func (c *amd64Ctx) x87PortableCompareStatus(left, right x87Value) string {
	equal, less, unordered := c.x87PortableCompare(left, right)
	c3 := c.x87PortableIR("or i1 %s, %s", equal, unordered)
	c0 := c.x87PortableIR("or i1 %s, %s", less, unordered)
	c3 = c.x87PortableIR("select i1 %s, i16 16384, i16 0", c3)
	c0 = c.x87PortableIR("select i1 %s, i16 256, i16 0", c0)
	c2 := c.x87PortableIR("select i1 %s, i16 1024, i16 0", unordered)
	status := c.x87PortableIR("or i16 %s, %s", c3, c0)
	return c.x87PortableIR("or i16 %s, %s", status, c2)
}

func (c *amd64Ctx) setX87CompareFlags(status string) {
	for _, bit := range []struct {
		mask int
		slot string
	}{{0x4000, c.flagsZSlot}, {0x0100, c.flagsCFSlot}, {0x0400, c.flagsPFSlot}} {
		masked, condition := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i16 %s, %d\n", masked, status, bit.mask)
		fmt.Fprintf(c.b, "  %%%s = icmp ne i16 %%%s, 0\n", condition, masked)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", condition, bit.slot)
	}
	for _, slot := range []string{c.flagsSltSlot, c.flagsOFSlot, c.flagsAFSlot} {
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", slot)
	}
}
