package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) storeFlag(slot string, v string) {
	mask := c.arm64FlagSlotMask(slot)
	c.flagsKnown |= mask
	if c.flagFlow != nil {
		block := &c.flagFlow.blocks[c.flagFlow.current]
		block.effects = append(block.effects, arm64FlagEffect{write: mask})
	}
	c.recordMachineRegister(Reg(slot), 1, true)
	fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", v, slot)
}

func (c *arm64Ctx) arm64FlagSlotMask(slot string) arm64FlagMask {
	switch slot {
	case c.flagsNSlot:
		return arm64FlagN
	case c.flagsZSlot:
		return arm64FlagZ
	case c.flagsCSlot:
		return arm64FlagC
	case c.flagsVSlot:
		return arm64FlagV
	}
	return 0
}

func (c *arm64Ctx) invalidateARM64Flags(mask arm64FlagMask) {
	c.flagsKnown &^= mask
	if mask != 0 {
		c.flagsWritten = false
	}
	if c.flagFlow != nil {
		block := &c.flagFlow.blocks[c.flagFlow.current]
		block.effects = append(block.effects, arm64FlagEffect{invalidate: mask})
	}
	for _, slot := range []string{c.flagsNSlot, c.flagsZSlot, c.flagsCSlot, c.flagsVSlot} {
		if c.arm64FlagSlotMask(slot)&mask != 0 {
			c.recordMachineUnavailable(Reg(slot))
		}
	}
}

func (c *arm64Ctx) requireARM64Flags(mask arm64FlagMask, condition string) error {
	if mask == 0 {
		return nil
	}
	if c.flagFlow != nil {
		block := &c.flagFlow.blocks[c.flagFlow.current]
		block.effects = append(block.effects, arm64FlagEffect{read: mask, condition: condition})
		return nil // A complete reaching write may appear later in source order.
	}
	known := c.flagsKnown
	if c.flagsWritten {
		known = arm64FlagAll
	}
	if mask&^known != 0 {
		return fmt.Errorf("%w: arm64 condition %s has no prior flags write", ErrProbeNeedsContext, condition)
	}
	return nil
}

func arm64ConditionFlags(condition string) (arm64FlagMask, error) {
	switch strings.ToUpper(condition) {
	case "EQ", "NE":
		return arm64FlagZ, nil
	case "CS", "HS", "LO", "CC":
		return arm64FlagC, nil
	case "HI", "LS":
		return arm64FlagC | arm64FlagZ, nil
	case "LT", "GE":
		return arm64FlagN | arm64FlagV, nil
	case "GT", "LE":
		return arm64FlagN | arm64FlagV | arm64FlagZ, nil
	case "MI", "PL":
		return arm64FlagN, nil
	case "VS", "VC":
		return arm64FlagV, nil
	case "AL", "NV":
		return 0, nil
	default:
		return 0, fmt.Errorf("arm64: unsupported condition %q", condition)
	}
}

func (c *arm64Ctx) setFlagsSub(dst, src, res string) {
	c.setFlagsSubWithCarry(dst, src, res, "")
}

func (c *arm64Ctx) setFlagsSubWithCarry(dst, src, res, carryValue string) {
	// NZCV for subtraction:
	// Z: res==0
	// N: res<0 (signed)
	// C: dst >= src (unsigned, no borrow)
	// V: signed overflow for dst - src
	c.flagsWritten = true

	z := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i64 %s, 0\n", z, res)
	n := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt i64 %s, 0\n", n, res)
	carry := carryValue
	if carry == "" {
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp uge i64 %s, %s\n", t, dst, src)
		carry = "%" + t
	}

	// overflow = ((dst ^ src) & (dst ^ res)) < 0
	x1 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor i64 %s, %s\n", x1, dst, src)
	x2 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor i64 %s, %s\n", x2, dst, res)
	x3 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, %%%s\n", x3, x1, x2)
	ov := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt i64 %%%s, 0\n", ov, x3)

	c.storeFlag(c.flagsZSlot, "%"+z)
	c.storeFlag(c.flagsNSlot, "%"+n)
	c.storeFlag(c.flagsCSlot, carry)
	c.storeFlag(c.flagsVSlot, "%"+ov)
}

func (c *arm64Ctx) setFlagsSub32(dst, src, res string) {
	c.setFlagsSub32WithCarry(dst, src, res, "")
}

func (c *arm64Ctx) setFlagsSub32WithCarry(dst, src, res, carryValue string) {
	// SUBSW computes NZCV from the low 32 bits, before the architectural
	// zero-extension of the result into the 64-bit register file.
	c.flagsWritten = true

	z := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %s, 0\n", z, res)
	n := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt i32 %s, 0\n", n, res)
	carry := carryValue
	if carry == "" {
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp uge i32 %s, %s\n", t, dst, src)
		carry = "%" + t
	}
	x1 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor i32 %s, %s\n", x1, dst, src)
	x2 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor i32 %s, %s\n", x2, dst, res)
	x3 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, %%%s\n", x3, x1, x2)
	ov := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt i32 %%%s, 0\n", ov, x3)

	c.storeFlag(c.flagsZSlot, "%"+z)
	c.storeFlag(c.flagsNSlot, "%"+n)
	c.storeFlag(c.flagsCSlot, carry)
	c.storeFlag(c.flagsVSlot, "%"+ov)
}

func (c *arm64Ctx) setFlagsAdd(dst, src, res string) {
	c.setFlagsAddWithCarry(dst, src, res, "")
}

func (c *arm64Ctx) setFlagsAddWithCarry(dst, src, res, carryValue string) {
	// NZCV for addition:
	// Z: res==0
	// N: res<0 (signed)
	// C: carry out (unsigned overflow) => res < dst
	// V: signed overflow for dst + src
	c.flagsWritten = true

	z := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i64 %s, 0\n", z, res)
	n := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt i64 %s, 0\n", n, res)
	carry := carryValue
	if carry == "" {
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ult i64 %s, %s\n", t, res, dst)
		carry = "%" + t
	}

	// overflow = (~(dst ^ src) & (dst ^ res)) < 0
	x1 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor i64 %s, %s\n", x1, dst, src)
	nx1 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor i64 %%%s, -1\n", nx1, x1)
	x2 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor i64 %s, %s\n", x2, dst, res)
	x3 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, %%%s\n", x3, nx1, x2)
	ov := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt i64 %%%s, 0\n", ov, x3)

	c.storeFlag(c.flagsZSlot, "%"+z)
	c.storeFlag(c.flagsNSlot, "%"+n)
	c.storeFlag(c.flagsCSlot, carry)
	c.storeFlag(c.flagsVSlot, "%"+ov)
}

func (c *arm64Ctx) setFlagsAdd32(dst, src, res string) {
	c.setFlagsAdd32WithCarry(dst, src, res, "")
}

func (c *arm64Ctx) setFlagsAdd32WithCarry(dst, src, res, carryValue string) {
	// ADDSW/CMNW compute flags from the low 32-bit sum.
	c.flagsWritten = true

	z := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %s, 0\n", z, res)
	n := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt i32 %s, 0\n", n, res)
	carry := carryValue
	if carry == "" {
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ult i32 %s, %s\n", t, res, dst)
		carry = "%" + t
	}
	x1 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor i32 %s, %s\n", x1, dst, src)
	nx1 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor i32 %%%s, -1\n", nx1, x1)
	x2 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor i32 %s, %s\n", x2, dst, res)
	x3 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, %%%s\n", x3, nx1, x2)
	ov := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt i32 %%%s, 0\n", ov, x3)

	c.storeFlag(c.flagsZSlot, "%"+z)
	c.storeFlag(c.flagsNSlot, "%"+n)
	c.storeFlag(c.flagsCSlot, carry)
	c.storeFlag(c.flagsVSlot, "%"+ov)
}

func (c *arm64Ctx) setConditionalCompareFlags(cond, lhs, rhs string, nzcv int64, word, add bool) error {
	predicate, err := c.condValue(cond)
	if err != nil {
		return err
	}
	typeName := "i64"
	if word {
		typeName = "i32"
	}
	result := c.newTmp()
	if add {
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", result, typeName, lhs, rhs)
	} else {
		fmt.Fprintf(c.b, "  %%%s = sub %s %s, %s\n", result, typeName, lhs, rhs)
	}
	z := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, 0\n", z, typeName, result)
	n := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %%%s, 0\n", n, typeName, result)
	carry := c.newTmp()
	if add {
		fmt.Fprintf(c.b, "  %%%s = icmp ult %s %%%s, %s\n", carry, typeName, result, lhs)
	} else {
		fmt.Fprintf(c.b, "  %%%s = icmp uge %s %s, %s\n", carry, typeName, lhs, rhs)
	}
	x1 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", x1, typeName, lhs, rhs)
	if add {
		nx1 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor %s %%%s, -1\n", nx1, typeName, x1)
		x1 = nx1
	}
	x2 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor %s %s, %%%s\n", x2, typeName, lhs, result)
	x3 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %%%s\n", x3, typeName, x1, x2)
	v := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %%%s, 0\n", v, typeName, x3)

	selectFlag := func(computed string, fallback bool) string {
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, i1 %s, i1 %t\n", selected, predicate, computed, fallback)
		return "%" + selected
	}
	c.flagsWritten = true
	c.storeFlag(c.flagsNSlot, selectFlag("%"+n, nzcv&8 != 0))
	c.storeFlag(c.flagsZSlot, selectFlag("%"+z, nzcv&4 != 0))
	c.storeFlag(c.flagsCSlot, selectFlag("%"+carry, nzcv&2 != 0))
	c.storeFlag(c.flagsVSlot, selectFlag("%"+v, nzcv&1 != 0))
	return nil
}

func (c *arm64Ctx) setFlagsLogic(res string) {
	// ANDS-like: update N/Z; set C/V to 0 (good enough for current corpus).
	c.flagsWritten = true

	z := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i64 %s, 0\n", z, res)
	n := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt i64 %s, 0\n", n, res)

	c.storeFlag(c.flagsZSlot, "%"+z)
	c.storeFlag(c.flagsNSlot, "%"+n)
	c.storeFlag(c.flagsCSlot, "false")
	c.storeFlag(c.flagsVSlot, "false")
}

func (c *arm64Ctx) setFlagsLogic32(res string) {
	c.flagsWritten = true

	z := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %s, 0\n", z, res)
	n := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt i32 %s, 0\n", n, res)

	c.storeFlag(c.flagsZSlot, "%"+z)
	c.storeFlag(c.flagsNSlot, "%"+n)
	c.storeFlag(c.flagsCSlot, "false")
	c.storeFlag(c.flagsVSlot, "false")
}

func (c *arm64Ctx) condValue(cond string) (string, error) {
	mask, err := arm64ConditionFlags(cond)
	if err != nil {
		return "", err
	}
	if err := c.requireARM64Flags(mask, cond); err != nil {
		return "", err
	}
	load := func(slot string) string {
		if c.arm64FlagSlotMask(slot)&mask == 0 {
			return "" // Never load unknown bits which this predicate does not read.
		}
		c.recordMachineRegister(Reg(slot), 1, false)
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", value, slot)
		return "%" + value
	}
	n, z := load(c.flagsNSlot), load(c.flagsZSlot)
	carry, v := load(c.flagsCSlot), load(c.flagsVSlot)

	not := func(x string) string {
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %s, true\n", t, x)
		return "%" + t
	}
	and := func(a, b string) string {
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i1 %s, %s\n", t, a, b)
		return "%" + t
	}
	or := func(a, b string) string {
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i1 %s, %s\n", t, a, b)
		return "%" + t
	}
	xor := func(a, b string) string {
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %s, %s\n", t, a, b)
		return "%" + t
	}
	eq := func(a, b string) string {
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i1 %s, %s\n", t, a, b)
		return "%" + t
	}

	switch strings.ToUpper(cond) {
	case "EQ":
		return z, nil
	case "NE":
		return not(z), nil
	case "CS":
		return carry, nil
	case "HS":
		return carry, nil
	case "LO":
		return not(carry), nil
	case "CC":
		return not(carry), nil
	case "HI":
		return and(carry, not(z)), nil
	case "LS":
		return or(not(carry), z), nil
	case "LT":
		return xor(n, v), nil
	case "GE":
		return eq(n, v), nil
	case "GT":
		return and(not(z), eq(n, v)), nil
	case "LE":
		return or(z, xor(n, v)), nil
	case "MI":
		return n, nil
	case "PL":
		return not(n), nil
	case "VS":
		return v, nil
	case "VC":
		return not(v), nil
	case "AL", "NV":
		return "true", nil
	default:
		return "", fmt.Errorf("arm64: unsupported condition %q", cond)
	}
}

type arm64Flags struct {
	kind  string // "cmp" or "res"
	dst   string // i64 SSA or constant
	src   string // i64 SSA or constant (for cmp)
	width LLVMType
}
