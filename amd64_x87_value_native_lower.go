package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) loadX87NativeOperand(source Operand, width byte) (x87Value, error) {
	if index, register := x87OperandReg(source); register {
		return c.loadX87Value(index), nil
	}
	if width == 'B' || width == 'X' {
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
		return c.x87NativeFromFloat(value, bits), nil
	}
	bits := 16
	if width == 'L' {
		bits = 32
	} else if width == 'V' {
		bits = 64
	} else if width != 'W' {
		return "", fmt.Errorf("unsupported x87 native scalar width %c", width)
	}
	value, err := c.loadStackValue(source, bits)
	if err != nil {
		return "", err
	}
	return c.x87NativeFromSigned(value, bits), nil
}

func (c *amd64Ctx) storeX87NativeOperand(destination Operand, value x87Value, width byte) error {
	if index, register := x87OperandReg(destination); register {
		c.storeX87Value(index, value)
		return nil
	}
	if width == 'B' || width == 'X' {
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
		return c.storeX87TypedMemory(destination, typ, c.x87NativeToFloat(value, bits))
	}
	if width == 'W' {
		bits = 16
	} else if width == 'L' {
		bits = 32
	} else if width != 'V' {
		return fmt.Errorf("unsupported x87 native scalar store width %c", width)
	}
	return c.storeX87TypedMemory(destination, amd64IntegerTypeForBits(bits), c.x87NativeToSigned(value, bits))
}

// This is a backend for the existing typed forms, not a second source grammar.
// Source availability, exact raw replay and conditional memory roles are still
// checked before lowering. No native C long-double ABI is involved.
func (c *amd64Ctx) lowerX87NativeValue(op Op, ins Instr, form x86X87ValueForm, typed bool) (bool, error) {
	if !c.x87NativeValues {
		return false, nil
	}
	if !typed && len(ins.Args) != 0 {
		return false, nil // The existing non-value grammar reports the error.
	}
	if typed {
		switch form.spec.kind {
		case x86X87FloatMove, x86X87IntegerMove:
			if form.push {
				value, err := c.loadX87NativeOperand(form.source, form.spec.width)
				if err != nil {
					return true, err
				}
				return true, c.pushX87Value(value)
			}
			index, register := x87OperandReg(form.source)
			if !register {
				return true, fmt.Errorf("%s lacks a typed x87 value source", op)
			}
			if err := c.storeX87NativeOperand(form.destination, c.loadX87Value(index), form.spec.width); err != nil {
				return true, err
			}
			for count := uint8(0); count < form.spec.pop; count++ {
				c.popX87Value()
			}
			return true, nil
		case x86X87Arithmetic:
			source, err := c.loadX87NativeOperand(ins.Args[0], form.spec.width)
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
			result, _, _ := c.evaluateX87Native(instruction+" %st(1), %st(0)", []x87Value{left, right}, 1, 2)
			c.storeX87Value(destination, result)
			if form.spec.pop != 0 {
				c.popX87Value()
			}
			return true, nil
		case x86X87Compare:
			left, err := c.loadX87NativeOperand(form.left, 'D')
			if err != nil {
				return true, err
			}
			right, err := c.loadX87NativeOperand(form.right, form.spec.width)
			if err != nil {
				return true, err
			}
			instruction := "fcom"
			if strings.HasPrefix(string(op), "FUCOM") {
				instruction = "fucom"
			}
			_, _, status := c.evaluateX87Native(instruction+" %st(1)", []x87Value{left, right}, 0, 2)
			if form.spec.directFlags {
				c.setX87NativeCompareFlags(status)
			} else {
				c.projectX87NativeStatus(status, 0x4700)
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
		value, _, _ := c.evaluateX87Native(strings.ToLower(string(op)), nil, 1, 1)
		return true, c.pushX87Value(value)
	case "FABS", "FCHS", "FSQRT", "FRNDINT", "F2XM1", "FSIN", "FCOS":
		value, _, status := c.evaluateX87Native(strings.ToLower(string(op)), []x87Value{c.loadX87Value(0)}, 1, 1)
		c.storeX87Value(0, value)
		if op == "FSIN" || op == "FCOS" {
			c.projectX87NativeStatus(status, 0x0400)
		}
	case "FPTAN", "FSINCOS", "FXTRACT":
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
			c.projectX87NativeStatus(status, 0x0400)
		}
	case "FPATAN", "FYL2X", "FYL2XP1", "FSCALE", "FPREM", "FPREM1":
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
			c.projectX87NativeStatus(status, 0x4700)
		}
	case "FTST", "FXAM":
		_, _, status := c.evaluateX87Native(strings.ToLower(string(op)), []x87Value{c.loadX87Value(0)}, 0, 1)
		c.projectX87NativeStatus(status, 0x4700)
	case "FDECSTP", "FINCSTP":
		c.rotateX87Values(op == "FINCSTP")
	default:
		return false, nil
	}
	return true, nil
}

func (c *amd64Ctx) setX87NativeCompareFlags(status string) {
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
