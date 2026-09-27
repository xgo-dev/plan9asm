package plan9asm

import (
	"fmt"
	"strings"
)

// lowerConditionalMove implements the complete Go 1.27 yml_rl conditional
// move table: every x86 condition code at W/L/Q width, with a register or
// memory source and a GP-register destination.
func (c *amd64Ctx) lowerConditionalMove(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	switch baseOp {
	case "CMOVWCC", "CMOVWCS", "CMOVWEQ", "CMOVWGE", "CMOVWGT", "CMOVWHI", "CMOVWLE", "CMOVWLS",
		"CMOVWLT", "CMOVWMI", "CMOVWNE", "CMOVWOC", "CMOVWOS", "CMOVWPC", "CMOVWPL", "CMOVWPS",
		"CMOVLCC", "CMOVLCS", "CMOVLEQ", "CMOVLGE", "CMOVLGT", "CMOVLHI", "CMOVLLE", "CMOVLLS",
		"CMOVLLT", "CMOVLMI", "CMOVLNE", "CMOVLOC", "CMOVLOS", "CMOVLPC", "CMOVLPL", "CMOVLPS",
		"CMOVQCC", "CMOVQCS", "CMOVQEQ", "CMOVQGE", "CMOVQGT", "CMOVQHI", "CMOVQLE", "CMOVQLS",
		"CMOVQLT", "CMOVQMI", "CMOVQNE", "CMOVQOC", "CMOVQOS", "CMOVQPC", "CMOVQPL", "CMOVQPS":
		// handled below
	default:
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("amd64 %s does not accept instruction suffixes: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s expects register/memory source and register destination: %q", baseOp, ins.Raw)
	}
	if ins.Args[0].Kind != OpReg && !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("amd64 %s source must be a register or memory operand: %q", baseOp, ins.Raw)
	}
	if _, ok := amd64FullRegBase(ins.Args[1].Reg); !ok {
		return true, false, fmt.Errorf("amd64 %s destination must be a GP register: %q", baseOp, ins.Raw)
	}
	if ins.Args[0].Kind == OpReg {
		if _, ok := amd64FullRegBase(ins.Args[0].Reg); !ok {
			return true, false, fmt.Errorf("amd64 %s register source must be a GP register: %q", baseOp, ins.Raw)
		}
	}

	ty := I64
	switch baseOp[4] {
	case 'W':
		ty = I16
	case 'L':
		ty = I32
	case 'Q':
	default:
		panic("conditional move width precheck drift")
	}
	src, err := c.evalIntSized(ins.Args[0], ty)
	if err != nil {
		return true, false, err
	}
	cur, err := c.evalIntSized(ins.Args[1], ty)
	if err != nil {
		return true, false, err
	}
	condition, err := c.x86Condition(baseOp[5:])
	if err != nil {
		return true, false, err
	}
	selected := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, %s %s, %s %s\n", selected, condition, ty, src, ty, cur)
	return true, false, c.storeRegSized(ins.Args[1].Reg, ty, "%"+selected)
}

func (c *amd64Ctx) x86Condition(code string) (string, error) {
	invert := func(value string) string {
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %s, true\n", out, value)
		return "%" + out
	}
	combine := func(instruction, left, right string) string {
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s i1 %s, %s\n", out, instruction, left, right)
		return "%" + out
	}

	switch code {
	case "CC":
		return invert(c.loadFlag(c.flagsCFSlot)), nil
	case "CS":
		return c.loadFlag(c.flagsCFSlot), nil
	case "EQ":
		return c.loadFlag(c.flagsZSlot), nil
	case "GE", "GT", "LE", "LT":
		signedLess := combine("xor", c.loadFlag(c.flagsSltSlot), c.loadFlag(c.flagsOFSlot))
		switch code {
		case "LT":
			return signedLess, nil
		case "GE":
			return invert(signedLess), nil
		case "LE":
			return combine("or", c.loadFlag(c.flagsZSlot), signedLess), nil
		case "GT":
			return invert(combine("or", c.loadFlag(c.flagsZSlot), signedLess)), nil
		}
	case "HI":
		return combine("and", invert(c.loadFlag(c.flagsCFSlot)), invert(c.loadFlag(c.flagsZSlot))), nil
	case "LS":
		return combine("or", c.loadFlag(c.flagsCFSlot), c.loadFlag(c.flagsZSlot)), nil
	case "MI":
		return c.loadFlag(c.flagsSltSlot), nil
	case "NE":
		return invert(c.loadFlag(c.flagsZSlot)), nil
	case "OC":
		return invert(c.loadFlag(c.flagsOFSlot)), nil
	case "OS":
		return c.loadFlag(c.flagsOFSlot), nil
	case "PC":
		return invert(c.loadFlag(c.flagsPFSlot)), nil
	case "PL":
		return invert(c.loadFlag(c.flagsSltSlot)), nil
	case "PS":
		return c.loadFlag(c.flagsPFSlot), nil
	}
	return "", fmt.Errorf("unsupported x86 condition code %q", code)
}
