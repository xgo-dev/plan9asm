package arm64

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"strings"
)

func (c *arm64Ctx) storeFlag(slot string, v string) {
	fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", v, slot)
}

func (c *arm64Ctx) setFlagsSub(dst, src, res string) {
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
	carry := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp uge i64 %s, %s\n", carry, dst, src)

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
	c.storeFlag(c.flagsCSlot, "%"+carry)
	c.storeFlag(c.flagsVSlot, "%"+ov)
}

func (c *arm64Ctx) setFlagsSub32(dst, src, res string) {
	// SUBSW computes NZCV from the low 32 bits, before the architectural
	// zero-extension of the result into the 64-bit register file.
	c.flagsWritten = true

	z := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %s, 0\n", z, res)
	n := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt i32 %s, 0\n", n, res)
	carry := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp uge i32 %s, %s\n", carry, dst, src)
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
	c.storeFlag(c.flagsCSlot, "%"+carry)
	c.storeFlag(c.flagsVSlot, "%"+ov)
}

func (c *arm64Ctx) setFlagsAdd(dst, src, res string) {
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
	carry := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ult i64 %s, %s\n", carry, res, dst)

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
	c.storeFlag(c.flagsCSlot, "%"+carry)
	c.storeFlag(c.flagsVSlot, "%"+ov)
}

func (c *arm64Ctx) setFlagsAdd32(dst, src, res string) {
	c.flagsWritten = true

	z := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %s, 0\n", z, res)
	n := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt i32 %s, 0\n", n, res)
	carry := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ult i32 %s, %s\n", carry, res, dst)

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
	c.storeFlag(c.flagsCSlot, "%"+carry)
	c.storeFlag(c.flagsVSlot, "%"+ov)
}

// setFlagsAddWithCarry computes exact AArch64 AddWithCarry(x, y, cIn) NZCV flags
// for ADCS/ADCSW (y=src), SBCS/SBCSW (y=~src), and NGCS/NGCSW (x=0, y=~src).
func (c *arm64Ctx) setFlagsAddWithCarry(width uint16, x, y, cIn, res string) {
	c.flagsWritten = true

	ty, wideTy, shift := "i64", "i128", 64
	if width == 32 {
		ty, wideTy, shift = "i32", "i64", 32
	}

	z := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, 0\n", z, ty, res)
	n := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, 0\n", n, ty, res)

	xu, yu, cu, u1, u2, ush, carry := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", xu, ty, x, wideTy)
	fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", yu, ty, y, wideTy)
	fmt.Fprintf(c.b, "  %%%s = zext i1 %s to %s\n", cu, cIn, wideTy)
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", u1, wideTy, xu, yu)
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", u2, wideTy, u1, cu)
	fmt.Fprintf(c.b, "  %%%s = lshr %s %%%s, %d\n", ush, wideTy, u2, shift)
	fmt.Fprintf(c.b, "  %%%s = icmp ne %s %%%s, 0\n", carry, wideTy, ush)

	xs, ys, s1, s2, rs, ov := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", xs, ty, x, wideTy)
	fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", ys, ty, y, wideTy)
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", s1, wideTy, xs, ys)
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", s2, wideTy, s1, cu)
	fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", rs, ty, res, wideTy)
	fmt.Fprintf(c.b, "  %%%s = icmp ne %s %%%s, %%%s\n", ov, wideTy, s2, rs)

	c.storeFlag(c.flagsZSlot, "%"+z)
	c.storeFlag(c.flagsNSlot, "%"+n)
	c.storeFlag(c.flagsCSlot, "%"+carry)
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
	if !c.flagsWritten {
		return "", fmt.Errorf("%w: arm64 condition %s has no prior flags write", asm.ErrProbeNeedsContext, cond)
	}
	ldN := c.newTmp()
	ldZ := c.newTmp()
	ldC := c.newTmp()
	ldV := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", ldN, c.flagsNSlot)
	fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", ldZ, c.flagsZSlot)
	fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", ldC, c.flagsCSlot)
	fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", ldV, c.flagsVSlot)

	n := "%" + ldN
	z := "%" + ldZ
	carry := "%" + ldC
	v := "%" + ldV

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
