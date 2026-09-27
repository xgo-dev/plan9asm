package plan9asm

import "fmt"

type arm64RawSystemRegister struct {
	read     bool
	encoding uint16
	reg      int
}

// decodeARM64RawSystemRegister covers the complete MRS/MSR (register) encoding
// fields: both directions, every 15-bit architectural system-register value,
// and every Xt value (including XZR).
func decodeARM64RawSystemRegister(word uint32) (arm64RawSystemRegister, bool) {
	fixed := word & 0xfff00000
	if fixed != 0xd5300000 && fixed != 0xd5100000 {
		return arm64RawSystemRegister{}, false
	}
	return arm64RawSystemRegister{
		read:     fixed == 0xd5300000,
		encoding: uint16((word >> 5) & 0x7fff),
		reg:      int(word & 31),
	}, true
}

func arm64EncodedSystemRegisterName(encoding uint16) string {
	op0 := 2 + int((encoding>>14)&1)
	op1 := int((encoding >> 11) & 7)
	crn := int((encoding >> 7) & 15)
	crm := int((encoding >> 3) & 15)
	op2 := int(encoding & 7)
	return fmt.Sprintf("S%d_%d_C%d_C%d_%d", op0, op1, crn, crm, op2)
}

func (c *arm64Ctx) lowerRawSystemRegister(form arm64RawSystemRegister) error {
	sysreg := arm64EncodedSystemRegisterName(form.encoding)
	if form.read {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i64 asm sideeffect %q, %q()\n", value, "mrs $0, "+sysreg, "=r,~{memory}")
		if form.reg == 31 {
			return nil
		}
		return c.storeReg(Reg(fmt.Sprintf("R%d", form.reg)), "%"+value)
	}
	value := "0"
	if form.reg != 31 {
		var err error
		value, err = c.loadReg(Reg(fmt.Sprintf("R%d", form.reg)))
		if err != nil {
			return err
		}
	}
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i64 %s)\n", "msr "+sysreg+", $0", "r,~{memory}", value)
	return nil
}
