package plan9asm

import "fmt"

type armRawSXTB struct {
	condition   string
	rotation    int
	source      int
	destination int
}

func armConditionName(code int) string {
	return [...]string{"EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC", "HI", "LS", "GE", "LT", "GT", "LE", "AL"}[code]
}

// decodeARMRawSXTB covers every A32 SXTB Rd, Rm{, ROR #8|16|24}
// encoding: all four rotations, every register field, and the 15 executable
// conditions. Condition 0xf belongs to the unconditional instruction space.
func decodeARMRawSXTB(word uint32) (armRawSXTB, bool) {
	if word&0x0fff03f0 != 0x06af0070 || word>>28 == 0xf {
		return armRawSXTB{}, false
	}
	return armRawSXTB{
		condition:   armConditionName(int(word >> 28)),
		rotation:    int(word>>10&3) * 8,
		source:      int(word) & 15,
		destination: int(word>>12) & 15,
	}, true
}

func (c *armCtx) lowerRawSXTB(form armRawSXTB) error {
	if form.source == 15 || form.destination == 15 {
		return fmt.Errorf("arm SXTB cannot safely use PC")
	}
	source, err := c.loadReg(Reg(fmt.Sprintf("R%d", form.source)))
	if err != nil {
		return err
	}
	if form.rotation != 0 {
		rotated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.fshr.i32(i32 %s, i32 %s, i32 %d)\n", rotated, source, source, form.rotation)
		source = "%" + rotated
	}
	narrowed := c.newTmp()
	extended := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to i8\n", narrowed, source)
	fmt.Fprintf(c.b, "  %%%s = sext i8 %%%s to i32\n", extended, narrowed)
	return c.selectRegWrite(Reg(fmt.Sprintf("R%d", form.destination)), form.condition, "%"+extended)
}
