package plan9asm

import "fmt"

// lowerHardwareRandom implements every Go 1.27 yrdrand form for both the
// RDRAND and RDSEED instruction families. Both instructions return success in
// CF and architecturally clear OF, SF, ZF, AF, and PF.
func (c *amd64Ctx) lowerHardwareRandom(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, known, err := x86HardwareRandomProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}

	typ := amd64IntegerTypeForBits(spec.bits)
	call := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call { %s, i32 } @llvm.x86.%s.%d()\n", call, typ, spec.native, spec.bits)
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractvalue { %s, i32 } %%%s, 0\n", value, typ, call)
	status := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractvalue { %s, i32 } %%%s, 1\n", status, typ, call)

	// SP is a legal Yrl destination in Go's 386 table. This instruction is the
	// modeled write itself, so permit storeRegSized to update the virtual SP.
	previousAllowSPWrite := c.allowSPWrite
	if c.goarch == "386" && ins.Args[0].Reg == SP {
		c.allowSPWrite = true
	}
	err = c.storeRegSized(ins.Args[0].Reg, typ, "%"+value)
	c.allowSPWrite = previousAllowSPWrite
	if err != nil {
		return true, false, err
	}

	carry := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ne i32 %%%s, 0\n", carry, status)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", carry, c.flagsCFSlot)
	c.clearX86StatusFlags(x86StatusAll &^ x86StatusCF)
	return true, false, nil
}
