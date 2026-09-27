package plan9asm

import (
	"fmt"
	"strings"
)

type amd64LeaveSpec struct {
	bits int
}

// amd64LeaveSpecs is the complete Go 1.27 LEAVE grammar. W is shared,
// L is 386-only, and Q is amd64-only. The lowering models the architectural
// sequence SP = BP; POP BP against the translated register/address state.
var amd64LeaveSpecs = map[Op]amd64LeaveSpec{
	"LEAVEW": {bits: 16},
	"LEAVEL": {bits: 32},
	"LEAVEQ": {bits: 64},
}

func (c *amd64Ctx) lowerLeave(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64LeaveSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	if c.goarch == "386" && spec.bits == 64 {
		return true, false, fmt.Errorf("386 %s is absent from Go 1.27's 32-bit encoding table: %q", baseOp, ins.Raw)
	}
	if c.goarch != "386" && spec.bits == 32 {
		return true, false, fmt.Errorf("amd64 %s is absent from Go 1.27's 64-bit encoding table: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 0 {
		return true, false, fmt.Errorf("%s %s takes no operands: %q", c.goarch, baseOp, ins.Raw)
	}

	base, err := c.loadReg(BP)
	if err != nil {
		return true, false, err
	}
	address := base
	if c.goarch == "386" {
		low := c.truncI64(base, I32)
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", wide, low)
		address = "%" + wide
	}
	pointer := c.ptrFromAddrI64(address)
	typ := amd64StackLLVMType(spec.bits)
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s, align 1\n", value, typ, pointer)
	if err := c.storeRegSized(BP, typ, "%"+value); err != nil {
		return true, false, err
	}
	if c.goarch == "386" {
		address32 := c.truncI64(address, I32)
		next32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i32 %s, %d\n", next32, address32, spec.bits/8)
		next64 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", next64, next32)
		return true, false, c.storeRegUnchecked(SP, "%"+next64)
	}
	next := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", next, address, spec.bits/8)
	return true, false, c.storeRegUnchecked(SP, "%"+next)
}
