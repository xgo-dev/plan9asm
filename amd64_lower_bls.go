package plan9asm

import (
	"fmt"
	"strings"
)

// lowerLowestSetBitManipulation implements Go 1.27's complete _yblsil table:
// BLSI, BLSMSK, and BLSR at L/Q widths, with a Yml register-or-memory source
// and a Yrl destination register.
func (c *amd64Ctx) lowerLowestSetBitManipulation(op Op, ins Instr) (ok bool, terminated bool, err error) {
	name := strings.ToUpper(string(op))
	family := ""
	bits := 0
	switch name {
	case "BLSIL":
		family, bits = "BLSI", 32
	case "BLSIQ":
		family, bits = "BLSI", 64
	case "BLSMSKL":
		family, bits = "BLSMSK", 32
	case "BLSMSKQ":
		family, bits = "BLSMSK", 64
	case "BLSRL":
		family, bits = "BLSR", 32
	case "BLSRQ":
		family, bits = "BLSR", 64
	default:
		return false, false, nil
	}
	if len(ins.Args) != 2 {
		return true, false, fmt.Errorf("%s %s expects source, destination register: %q", c.goarch, name, ins.Raw)
	}
	source, destination := ins.Args[0], ins.Args[1]
	if source.Kind == OpReg {
		if !isX86YrlRegisterForArch(source.Reg, c.goarch) {
			return true, false, fmt.Errorf("%s %s source is outside Go 1.27's Yml class: %q", c.goarch, name, ins.Raw)
		}
	} else if source.Kind == OpSym && strings.HasPrefix(strings.TrimSpace(source.Sym), "$") || !isAMD64MemoryOperand(source) {
		return true, false, fmt.Errorf("%s %s source is outside Go 1.27's Yml class: %q", c.goarch, name, ins.Raw)
	}
	if destination.Kind != OpReg || !isX86YrlRegisterForArch(destination.Reg, c.goarch) {
		return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's Yrl class: %q", c.goarch, name, ins.Raw)
	}

	// VEX.W is ignored for this family in 32-bit mode. Go 1.27 therefore
	// accepts the Q spellings for 386 and emits the same 32-bit operation.
	typ := I32
	if bits == 64 && c.goarch != "386" {
		typ = I64
	}
	value, err := c.evalIntSized(source, typ)
	if err != nil {
		return true, false, err
	}
	minusOne := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub %s %s, 1\n", minusOne, typ, value)
	result := c.newTmp()
	carry := ""
	switch family {
	case "BLSI":
		negative := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub %s 0, %s\n", negative, typ, value)
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %%%s\n", result, typ, value, negative)
		carry = c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ne %s %s, 0\n", carry, typ, value)
	case "BLSMSK":
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, %%%s\n", result, typ, value, minusOne)
		carry = c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, 0\n", carry, typ, value)
	case "BLSR":
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %%%s\n", result, typ, value, minusOne)
		carry = c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, 0\n", carry, typ, value)
	}

	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", carry, c.flagsCFSlot)
	if family == "BLSMSK" {
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsZSlot)
	} else {
		zero := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, 0\n", zero, typ, result)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zero, c.flagsZSlot)
	}
	sign := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %%%s, 0\n", sign, typ, result)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", sign, c.flagsSltSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
	return true, false, c.storeRegSized(destination.Reg, typ, "%"+result)
}
