package plan9asm

import "fmt"

// lowerRawWord models the small set of flag-writing instructions emitted as
// raw encodings by generated Go assembly. Unknown WORD values remain ignored,
// matching the translator's existing permissive behavior for embedded opcodes.
func (c *arm64Ctx) lowerRawWord(ins Instr) error {
	if len(ins.Args) != 1 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" {
		return nil
	}

	word := uint32(ins.Args[0].Imm)
	switch {
	case word == 0xea00001f: // TST X0, X0 (ANDS XZR, X0, X0)
		value, err := c.loadReg("R0")
		if err != nil {
			return err
		}
		c.setFlagsLogic(value)
		return nil

	case word&0xff800000 == 0xf1000000: // SUBS Xd, Xn, #imm{, LSL #12}
		rn := (word >> 5) & 31
		rd := word & 31
		imm := int64((word >> 10) & 0xfff)
		if word&(1<<22) != 0 {
			imm <<= 12
		}

		srcReg := Reg(fmt.Sprintf("R%d", rn))
		if rn == 31 {
			srcReg = SP
		}
		src, err := c.loadReg(srcReg)
		if err != nil {
			return err
		}

		resTmp := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i64 %s, %d\n", resTmp, src, imm)
		res := "%" + resTmp
		if rd != 31 {
			if err := c.storeReg(Reg(fmt.Sprintf("R%d", rd)), res); err != nil {
				return err
			}
		}
		c.setFlagsSub(src, fmt.Sprintf("%d", imm), res)
		return nil
	}

	return nil
}
