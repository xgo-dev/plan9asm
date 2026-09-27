package plan9asm

import (
	"fmt"
	"strings"
)

// lowerHardwareRandom implements every Go 1.27 yrdrand form for both the
// RDRAND and RDSEED instruction families. Both instructions return success in
// CF and architecturally clear OF, SF, ZF, AF, and PF; AF is not otherwise
// modeled by the translator.
func (c *amd64Ctx) lowerHardwareRandom(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}

	family := ""
	bits := 0
	for _, candidate := range []string{"RDRAND", "RDSEED"} {
		if !strings.HasPrefix(baseOp, candidate) {
			continue
		}
		family = strings.ToLower(candidate)
		switch strings.TrimPrefix(baseOp, candidate) {
		case "W":
			bits = 16
		case "L":
			bits = 32
		case "Q":
			bits = 64
		default:
			return true, false, fmt.Errorf("%s %s requires a W, L, or Q width suffix: %q", c.goarch, candidate, ins.Raw)
		}
		break
	}
	if family == "" {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	if c.goarch == "386" && bits == 64 {
		return true, false, fmt.Errorf("386 %s is illegal in 32-bit mode: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 1 || ins.Args[0].Kind != OpReg || !isX86YrlRegisterForArch(ins.Args[0].Reg, c.goarch) {
		return true, false, fmt.Errorf("%s %s expects one general register: %q", c.goarch, baseOp, ins.Raw)
	}

	typ := amd64IntegerTypeForBits(bits)
	call := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call { %s, i32 } @llvm.x86.%s.%d()\n", call, typ, family, bits)
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
	for _, slot := range []string{c.flagsOFSlot, c.flagsSltSlot, c.flagsZSlot, c.flagsPFSlot} {
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", slot)
	}
	return true, false, nil
}
