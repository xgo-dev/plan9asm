package plan9asm

import "fmt"

// lowerRawWord models raw encodings only when their register and flag effects
// are known. Silently emitting nothing for an unknown machine instruction
// would report success while changing program semantics.
func (c *arm64Ctx) lowerRawWord(ins Instr) error {
	word, err := arm64RawWordValue(ins)
	if err != nil {
		return err
	}
	if family, _, ok := decodeARM64RawFloatFamily(word); ok {
		return family.lower(c, word)
	}
	if form, ok := decodeARM64RawException(word); ok {
		return c.lowerRawException(form)
	}
	if form, ok := decodeARM64RawTLBI(word); ok {
		return c.lowerRawTLBI(form)
	}
	if family, _, ok := decodeARM64RawStateFamily(word); ok {
		return family.lower(c, word)
	}
	if family, decoded, ok := decodeARM64RawSVEFamily(word); ok {
		return family.lower(c, decoded)
	}
	for _, family := range arm64RawSVEVectorFamilies {
		if family.matches(word) {
			return family.lower(c, word)
		}
	}
	if _, reservedLoad := arm64RawSVEUnsignedLoadRows[word&0xffe0e000]; reservedLoad {
		return fmt.Errorf("reserved ARM64 SVE load encoding %#08x: %q", word, ins.Raw)
	}
	if form, ok := decodeARM64RawSVELD1B(word); ok {
		return c.lowerRawSVELD1B(form)
	}
	if form, ok := decodeARM64RawSystemRegister(word); ok {
		return c.lowerRawSystemRegister(form)
	}
	if immediate, ok := decodeARM64RawHint(word); ok {
		c.emitARM64Hint(immediate)
		return nil
	}
	if family, _, ok := decodeARM64RawVectorFamily(word); ok {
		return family.lower(c, word)
	}
	if form, ok := decodeARM64RawStructureLane(word); ok {
		return c.lowerRawStructureLane(form)
	}
	if form, ok := decodeARM64RawLDnR(word); ok {
		return c.lowerRawLDnR(form)
	}
	if form, ok := decodeARM64RawMoveWide(word); ok {
		return c.lowerRawMoveWide(form)
	}
	if form, ok := decodeARM64RawSVEAddress(word); ok {
		return c.lowerRawSVEAddress(form)
	}
	if form, ok := decodeARM64RawSVECnt(word); ok {
		return c.lowerRawSVECnt(form)
	}
	if form, ok := decodeARM64RawBitfield(word); ok {
		return c.lowerRawBitfield(form)
	}
	if form, ok := decodeARM64RawSVEPTrue(word); ok {
		return c.lowerRawSVEPTrue(form)
	}
	if form, ok := decodeARM64RawSVELDST1D(word); ok {
		return c.lowerRawSVELDST1D(form)
	}
	if form, ok := decodeARM64RawSVELDST1W(word); ok {
		return c.lowerRawSVELDST1W(form)
	}
	if reduction, ok := decodeARM64RawSVEIntegerAddReduction(word); ok {
		return c.lowerARM64SVEAddReductionForm(
			reduction.spec,
			reduction.form,
			reduction.destination,
		)
	}
	if form, ok := decodeARM64RawSVEFloat(word); ok {
		return c.lowerRawSVEFloat(form)
	}
	if form, ok := decodeARM64RawSVELoadStore(word); ok {
		return c.lowerRawSVELoadStore(form)
	}
	if form, ok := decodeARM64RawSVEDupImmediate(word); ok {
		return c.lowerRawSVEDupImmediate(form)
	}
	if form, ok := decodeARM64RawSVEDupGeneral(word); ok {
		return c.lowerRawSVEDupGeneral(form)
	}
	if form, ok := decodeARM64RawSVEDupElement(word); ok {
		return c.lowerRawSVEDupElement(form)
	}
	if form, ok := decodeARM64RawSVEAdd(word); ok {
		return c.lowerRawSVEAdd(form)
	}
	if op, form, ok := decodeARM64RawSVEAddSub(word); ok {
		return c.lowerRawSVEAddSub(arm64SVEAddSubSpecs[op], form)
	}
	if form, ok := decodeARM64RawSVEShift(word); ok {
		return c.lowerRawSVELSR(form)
	}
	if form, ok := decodeARM64RawSVESelect(word); ok {
		return c.lowerRawSVESelect(form)
	}
	if form, ok := decodeARM64RawSVEEOR(word); ok {
		return c.lowerRawSVEEOR(form)
	}
	if form, ok := decodeARM64RawSVEPermute(word); ok {
		return c.lowerRawSVEPermute(form)
	}
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

	return fmt.Errorf("unsupported ARM64 WORD encoding %#08x: %q", word, ins.Raw)
}
