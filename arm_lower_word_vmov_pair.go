package plan9asm

import "fmt"

type armRawVMOVPair struct {
	toFloat     bool
	double      bool
	condition   string
	firstCore   int
	secondCore  int
	firstSingle int
	firstDouble int
}

// decodeARMRawVMOVPair covers both A32 directions between a pair of core
// registers and either two adjacent S registers or one D register, across
// every executable condition and encoded register field.
func decodeARMRawVMOVPair(word uint32) (armRawVMOVPair, bool) {
	const mask = uint32(0x0ff00fd0)

	toFloat := false
	double := false
	switch word & mask {
	case 0x0c400a10:
		toFloat = true
	case 0x0c500a10:
	case 0x0c400b10:
		toFloat = true
		double = true
	case 0x0c500b10:
		double = true
	default:
		return armRawVMOVPair{}, false
	}
	condition, ok := armRawCondition(word >> 28)
	if !ok {
		return armRawVMOVPair{}, false
	}
	firstSingle := int(word&0xf)*2 + int(word>>5&1)
	if !double && firstSingle >= 31 {
		return armRawVMOVPair{}, false
	}
	return armRawVMOVPair{
		toFloat:     toFloat,
		double:      double,
		condition:   condition,
		firstCore:   int(word>>12) & 15,
		secondCore:  int(word>>16) & 15,
		firstSingle: firstSingle,
		firstDouble: int(word&0xf) + int(word>>5&1)*16,
	}, true
}

func (c *armCtx) loadARMRawSingleBits(number int) (string, error) {
	wide, err := c.loadFReg(armRawVFPBackingReg(number, 32))
	if err != nil {
		return "", err
	}
	if number&1 != 0 {
		shifted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, 32\n", shifted, wide)
		wide = "%" + shifted
	}
	narrow := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", narrow, wide)
	return "%" + narrow, nil
}

func (c *armCtx) storeARMRawSingleBits(number int, value, condition string) error {
	reg := armRawVFPBackingReg(number, 32)
	old, err := c.loadFReg(reg)
	if err != nil {
		return err
	}
	extended := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", extended, value)
	newBits := "%" + extended
	if number&1 != 0 {
		shifted := c.newTmp()
		kept := c.newTmp()
		merged := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl i64 %s, 32\n", shifted, newBits)
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, 4294967295\n", kept, old)
		fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %%%s\n", merged, kept, shifted)
		newBits = "%" + merged
	} else {
		kept := c.newTmp()
		merged := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, -4294967296\n", kept, old)
		fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %s\n", merged, kept, newBits)
		newBits = "%" + merged
	}
	if condition != "" && condition != "AL" {
		conditionValue, err := c.condValue(condition)
		if err != nil {
			return err
		}
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, i64 %s, i64 %s\n", selected, conditionValue, newBits, old)
		newBits = "%" + selected
	}
	return c.storeFReg(reg, newBits)
}

func (c *armCtx) lowerRawVMOVPair(form armRawVMOVPair) error {
	if form.firstCore == 15 || form.secondCore == 15 {
		return fmt.Errorf("arm VMOV register pair cannot safely use PC")
	}
	firstCore := Reg(fmt.Sprintf("R%d", form.firstCore))
	secondCore := Reg(fmt.Sprintf("R%d", form.secondCore))
	if form.double {
		return c.lowerRawVMOVDoublePair(form, firstCore, secondCore)
	}
	if form.toFloat {
		first, err := c.loadReg(firstCore)
		if err != nil {
			return err
		}
		second, err := c.loadReg(secondCore)
		if err != nil {
			return err
		}
		if err := c.storeARMRawSingleBits(form.firstSingle, first, form.condition); err != nil {
			return err
		}
		return c.storeARMRawSingleBits(form.firstSingle+1, second, form.condition)
	}

	first, err := c.loadARMRawSingleBits(form.firstSingle)
	if err != nil {
		return err
	}
	second, err := c.loadARMRawSingleBits(form.firstSingle + 1)
	if err != nil {
		return err
	}
	if err := c.selectRegWrite(firstCore, form.condition, first); err != nil {
		return err
	}
	return c.selectRegWrite(secondCore, form.condition, second)
}

func (c *armCtx) lowerRawVMOVDoublePair(form armRawVMOVPair, firstCore, secondCore Reg) error {
	floatReg := armRawVFPBackingReg(form.firstDouble, 64)
	if form.toFloat {
		low, err := c.loadReg(firstCore)
		if err != nil {
			return err
		}
		high, err := c.loadReg(secondCore)
		if err != nil {
			return err
		}
		lowWide := c.newTmp()
		highWide := c.newTmp()
		shifted := c.newTmp()
		combined := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", lowWide, low)
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", highWide, high)
		fmt.Fprintf(c.b, "  %%%s = shl i64 %%%s, 32\n", shifted, highWide)
		fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %%%s\n", combined, lowWide, shifted)
		value := "%" + combined
		if form.condition != "" && form.condition != "AL" {
			condition, err := c.condValue(form.condition)
			if err != nil {
				return err
			}
			old, err := c.loadFReg(floatReg)
			if err != nil {
				return err
			}
			selected := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %s, i64 %s, i64 %s\n", selected, condition, value, old)
			value = "%" + selected
		}
		return c.storeFReg(floatReg, value)
	}

	wide, err := c.loadFReg(floatReg)
	if err != nil {
		return err
	}
	low := c.newTmp()
	shifted := c.newTmp()
	high := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", low, wide)
	fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, 32\n", shifted, wide)
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", high, shifted)
	if err := c.selectRegWrite(firstCore, form.condition, "%"+low); err != nil {
		return err
	}
	return c.selectRegWrite(secondCore, form.condition, "%"+high)
}
