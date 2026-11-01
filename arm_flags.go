package plan9asm

import (
	"fmt"
	"strings"
)

func (c *armCtx) storeFlag(slot string, v string) {
	fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", v, slot)
}

// captureHardwareFlags records the APSR condition flags immediately after an
// out-of-line call. ARM assembly is allowed to branch on flags produced by the
// callee (the Linux kuser CAS helper does this), while an LLVM call has no flag
// result in its type. Reading APSR keeps that machine-level contract explicit.
func (c *armCtx) captureHardwareFlags() {
	status := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call i32 asm sideeffect %q, %q()\n", status, "mrs $0, apsr", "=r,~{memory}")
	c.storeFlagsFromStatus("%" + status)
}

func (c *armCtx) storeFlagsFromStatus(status string) {
	for _, item := range []struct {
		shift int
		slot  string
	}{
		{31, c.flagsNSlot},
		{30, c.flagsZSlot},
		{29, c.flagsCSlot},
		{28, c.flagsVSlot},
	} {
		shifted := c.newTmp()
		flag := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i32 %s, %d\n", shifted, status, item.shift)
		fmt.Fprintf(c.b, "  %%%s = trunc i32 %%%s to i1\n", flag, shifted)
		c.storeFlag(item.slot, "%"+flag)
	}
	c.flagsWritten = true
}

// LLVM arithmetic does not carry Plan 9's modeled NZCV in physical APSR.
// Keep the physical non-NZCV status bits, but read the same condition state
// used by source predicates after a source flags write or typed native call.
func (c *armCtx) statusWithModeledNZCV(status string) string {
	if !c.flagsWritten {
		return status
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i32 %s, 268435455\n", result, status)
	for _, item := range []struct {
		shift int
		slot  string
	}{
		{31, c.flagsNSlot}, {30, c.flagsZSlot},
		{29, c.flagsCSlot}, {28, c.flagsVSlot},
	} {
		flag, wide, shifted, merged := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", flag, item.slot)
		fmt.Fprintf(c.b, "  %%%s = zext i1 %%%s to i32\n", wide, flag)
		fmt.Fprintf(c.b, "  %%%s = shl i32 %%%s, %d\n", shifted, wide, item.shift)
		fmt.Fprintf(c.b, "  %%%s = or i32 %%%s, %%%s\n", merged, result, shifted)
		result = merged
	}
	return "%" + result
}

func (c *armCtx) storeFlagCond(cond, slot, v string) error {
	if cond == "" || strings.EqualFold(cond, "AL") {
		c.storeFlag(slot, v)
		return nil
	}
	cv, err := c.condValue(cond)
	if err != nil {
		return err
	}
	oldV := c.newTmp()
	sel := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", oldV, slot)
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i1 %s, i1 %%%s\n", sel, cv, v, oldV)
	c.storeFlag(slot, "%"+sel)
	return nil
}

func (c *armCtx) setFlagsSub(cond, dst, src, res string) error {
	if cond != "" && !strings.EqualFold(cond, "AL") {
		return c.emitConditionalEffect(cond, func() error {
			return c.setFlagsSub("", dst, src, res)
		})
	}
	c.flagsWritten = true
	z := c.newTmp()
	n := c.newTmp()
	carry := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %s, 0\n", z, res)
	fmt.Fprintf(c.b, "  %%%s = icmp slt i32 %s, 0\n", n, res)
	fmt.Fprintf(c.b, "  %%%s = icmp uge i32 %s, %s\n", carry, dst, src)
	x1 := c.newTmp()
	x2 := c.newTmp()
	x3 := c.newTmp()
	ov := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor i32 %s, %s\n", x1, dst, src)
	fmt.Fprintf(c.b, "  %%%s = xor i32 %s, %s\n", x2, dst, res)
	fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, %%%s\n", x3, x1, x2)
	fmt.Fprintf(c.b, "  %%%s = icmp slt i32 %%%s, 0\n", ov, x3)
	if err := c.storeFlagCond(cond, c.flagsZSlot, "%"+z); err != nil {
		return err
	}
	if err := c.storeFlagCond(cond, c.flagsNSlot, "%"+n); err != nil {
		return err
	}
	if err := c.storeFlagCond(cond, c.flagsCSlot, "%"+carry); err != nil {
		return err
	}
	return c.storeFlagCond(cond, c.flagsVSlot, "%"+ov)
}

func (c *armCtx) setFlagsAdd(cond, dst, src, res string) error {
	if cond != "" && !strings.EqualFold(cond, "AL") {
		return c.emitConditionalEffect(cond, func() error {
			return c.setFlagsAdd("", dst, src, res)
		})
	}
	c.flagsWritten = true
	z := c.newTmp()
	n := c.newTmp()
	carry := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %s, 0\n", z, res)
	fmt.Fprintf(c.b, "  %%%s = icmp slt i32 %s, 0\n", n, res)
	fmt.Fprintf(c.b, "  %%%s = icmp ult i32 %s, %s\n", carry, res, dst)
	x1 := c.newTmp()
	nx1 := c.newTmp()
	x2 := c.newTmp()
	x3 := c.newTmp()
	ov := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor i32 %s, %s\n", x1, dst, src)
	fmt.Fprintf(c.b, "  %%%s = xor i32 %%%s, -1\n", nx1, x1)
	fmt.Fprintf(c.b, "  %%%s = xor i32 %s, %s\n", x2, dst, res)
	fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, %%%s\n", x3, nx1, x2)
	fmt.Fprintf(c.b, "  %%%s = icmp slt i32 %%%s, 0\n", ov, x3)
	if err := c.storeFlagCond(cond, c.flagsZSlot, "%"+z); err != nil {
		return err
	}
	if err := c.storeFlagCond(cond, c.flagsNSlot, "%"+n); err != nil {
		return err
	}
	if err := c.storeFlagCond(cond, c.flagsCSlot, "%"+carry); err != nil {
		return err
	}
	return c.storeFlagCond(cond, c.flagsVSlot, "%"+ov)
}

func (c *armCtx) setFlagsLogic(cond, res string) error {
	if cond != "" && !strings.EqualFold(cond, "AL") {
		return c.emitConditionalEffect(cond, func() error {
			return c.setFlagsLogic("", res)
		})
	}
	c.flagsWritten = true
	z := c.newTmp()
	n := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %s, 0\n", z, res)
	fmt.Fprintf(c.b, "  %%%s = icmp slt i32 %s, 0\n", n, res)
	if err := c.storeFlagCond(cond, c.flagsZSlot, "%"+z); err != nil {
		return err
	}
	return c.storeFlagCond(cond, c.flagsNSlot, "%"+n)
}

// Go's ARM C_RCON row encodes an eight-bit immediate rotated right by an
// even count. A nonzero rotation supplies C from bit 31; an unshifted register
// (including a materialized large constant) preserves C. AND's C_NCON row
// instead uses BIC with the complemented immediate (asm5 encoder type 114).
func armLogicalImmediateCarry(op string, source Operand) string {
	if source.Kind != OpImm || source.ImmRaw != "" {
		return ""
	}
	value := uint32(source.Imm)
	if op == "AND" && !armRotatedImmediateEncodable(value) && armRotatedImmediateEncodable(^value) {
		value = ^value
	}
	if value <= 255 || !armRotatedImmediateEncodable(value) {
		return ""
	}
	if value&(1<<31) != 0 {
		return "true"
	}
	return "false"
}

func (c *armCtx) setARMLogicalFlags(condition, result, carry string) error {
	if condition != "" && !strings.EqualFold(condition, "AL") {
		return c.emitConditionalEffect(condition, func() error {
			return c.setARMLogicalFlags("", result, carry)
		})
	}
	if err := c.setFlagsLogic("", result); err != nil {
		return err
	}
	if carry != "" {
		c.storeFlag(c.flagsCSlot, carry)
	}
	return nil
}

func (c *armCtx) condValue(cond string) (string, error) {
	if !c.flagsWritten {
		return "", fmt.Errorf("%w: arm condition %s has no prior flags write", ErrProbeNeedsContext, cond)
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
	case "CS", "HS":
		return carry, nil
	case "CC", "LO":
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
	case "AL":
		return "true", nil
	default:
		return "", fmt.Errorf("arm: unsupported condition %q", cond)
	}
}
