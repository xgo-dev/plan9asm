package plan9asm

import "fmt"

type armRawVFPMultiple struct {
	load      bool
	decrement bool
	writeback bool
	condition string
	base      int
	bits      int
	first     int
	count     int
}

// decodeARMRawVFPMultiple covers the complete A32 VLDM/VSTM IA and DB
// encoding family for contiguous S0..S31 and D0..D31 register lists. DB is
// architecturally a writeback form; encodings without W are rejected.
func decodeARMRawVFPMultiple(word uint32) (armRawVFPMultiple, bool) {
	if word&0x0e000e00 != 0x0c000a00 {
		return armRawVFPMultiple{}, false
	}
	condition, ok := armRawCondition(word >> 28)
	if !ok {
		return armRawVFPMultiple{}, false
	}
	p := word>>24&1 != 0
	u := word>>23&1 != 0
	if p == u || p && word>>21&1 == 0 {
		return armRawVFPMultiple{}, false
	}
	bits := 32
	if word>>8&1 != 0 {
		bits = 64
	}
	first := int(word>>12) & 15
	if bits == 32 {
		first = first*2 + int(word>>22&1)
	} else {
		first += int(word>>22&1) * 16
	}
	encodedCount := int(word & 0xff)
	if encodedCount == 0 || bits == 64 && encodedCount&1 != 0 {
		return armRawVFPMultiple{}, false
	}
	count := encodedCount
	if bits == 64 {
		count /= 2
	}
	if first+count > 32 {
		return armRawVFPMultiple{}, false
	}
	return armRawVFPMultiple{
		load:      word>>20&1 != 0,
		decrement: p,
		writeback: word>>21&1 != 0,
		condition: condition,
		base:      int(word>>16) & 15,
		bits:      bits,
		first:     first,
		count:     count,
	}, true
}

func (c *armCtx) lowerRawVFPMultiple(form armRawVFPMultiple) error {
	if form.base == 15 {
		return fmt.Errorf("arm VFP multiple transfer cannot safely use PC as its base")
	}
	if form.condition != "" && form.condition != "AL" {
		condition := form.condition
		form.condition = "AL"
		return c.emitConditionalEffect(condition, func() error {
			return c.lowerRawVFPMultiple(form)
		})
	}

	baseReg := Reg(fmt.Sprintf("R%d", form.base))
	base, err := c.loadReg(baseReg)
	if err != nil {
		return err
	}
	bytes := form.count * (form.bits / 8)
	address := base
	if form.decrement {
		adjusted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i32 %s, %d\n", adjusted, base, bytes)
		address = "%" + adjusted
	}
	for i := 0; i < form.count; i++ {
		itemAddress := address
		if offset := i * (form.bits / 8); offset != 0 {
			adjusted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i32 %s, %d\n", adjusted, address, offset)
			itemAddress = "%" + adjusted
		}
		pointer := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i32 %s to ptr\n", pointer, itemAddress)
		register := form.first + i
		if form.load {
			value := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load i%d, ptr %%%s, align 1\n", value, form.bits, pointer)
			if form.bits == 32 {
				if err := c.storeARMRawSingleBits(register, "%"+value, ""); err != nil {
					return err
				}
			} else if err := c.storeFReg(armRawVFPBackingReg(register, 64), "%"+value); err != nil {
				return err
			}
			continue
		}

		var value string
		if form.bits == 32 {
			value, err = c.loadARMRawSingleBits(register)
		} else {
			value, err = c.loadFReg(armRawVFPBackingReg(register, 64))
		}
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store i%d %s, ptr %%%s, align 1\n", form.bits, value, pointer)
	}
	if form.writeback {
		updated := c.newTmp()
		operation := "add"
		if form.decrement {
			operation = "sub"
		}
		fmt.Fprintf(c.b, "  %%%s = %s i32 %s, %d\n", updated, operation, base, bytes)
		return c.storeReg(baseReg, "%"+updated)
	}
	return nil
}
