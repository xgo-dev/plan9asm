package plan9asm

import "fmt"

func decodeARM64RawICIVAU(word uint32) (Reg, bool) {
	if word&0xffffffe0 != 0xd50b7520 {
		return "", false
	}
	if word&31 == 31 {
		return ZR, true
	}
	return Reg(fmt.Sprintf("R%d", word&31)), true
}

func (c *arm64Ctx) lowerRawICIVAU(reg Reg) error {
	if reg == ZR {
		fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q()\n", "ic ivau, xzr", "~{memory}")
		return nil
	}
	value, err := c.loadReg(reg)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i64 %s)\n", "ic ivau, $0", "r,~{memory}", value)
	return nil
}
