package plan9asm

import "fmt"

type armRawVFPLoadStore struct {
	load      bool
	add       bool
	condition string
	base      int
	bits      int
	register  int
	offset    int
}

// decodeARMRawVFPLoadStore covers classic A32 VLDR/VSTR immediate-offset
// forms: both transfer widths, offset signs, all executable conditions,
// S0..S31 and D0..D31, and the complete 8-bit scaled offset field.
func decodeARMRawVFPLoadStore(word uint32) (armRawVFPLoadStore, bool) {
	const variable = uint32(0xf0000000 | 0x00800000 | 0x00400000 |
		0x00100000 | 0x000f0000 | 0x0000f000 | 0x00000100 | 0x000000ff)
	const base = uint32(0x0d000a00)
	if word&^variable != base {
		return armRawVFPLoadStore{}, false
	}
	condition, ok := armRawCondition(word >> 28)
	if !ok {
		return armRawVFPLoadStore{}, false
	}
	bits := 32
	register := int(word>>12) & 15
	if word>>8&1 != 0 {
		bits = 64
		register += int(word>>22&1) * 16
	} else {
		register = register*2 + int(word>>22&1)
	}
	return armRawVFPLoadStore{
		load:      word>>20&1 != 0,
		add:       word>>23&1 != 0,
		condition: condition,
		base:      int(word>>16) & 15,
		bits:      bits,
		register:  register,
		offset:    int(word&0xff) * 4,
	}, true
}

func (c *armCtx) lowerRawVFPLoadStore(form armRawVFPLoadStore) error {
	if form.base == 15 {
		return fmt.Errorf("arm VFP immediate transfer cannot safely use PC as its base")
	}
	if form.condition != "" && form.condition != "AL" {
		condition := form.condition
		form.condition = "AL"
		return c.emitConditionalEffect(condition, func() error {
			return c.lowerRawVFPLoadStore(form)
		})
	}
	base, err := c.loadReg(Reg(fmt.Sprintf("R%d", form.base)))
	if err != nil {
		return err
	}
	address := base
	if form.offset != 0 {
		adjusted := c.newTmp()
		operation := "sub"
		if form.add {
			operation = "add"
		}
		fmt.Fprintf(c.b, "  %%%s = %s i32 %s, %d\n", adjusted, operation, base, form.offset)
		address = "%" + adjusted
	}
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i32 %s to ptr\n", pointer, address)
	if form.load {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i%d, ptr %%%s, align 1\n", value, form.bits, pointer)
		if form.bits == 32 {
			return c.storeARMRawSingleBits(form.register, "%"+value, "")
		}
		return c.storeFReg(armRawVFPBackingReg(form.register, 64), "%"+value)
	}
	var value string
	if form.bits == 32 {
		value, err = c.loadARMRawSingleBits(form.register)
	} else {
		value, err = c.loadFReg(armRawVFPBackingReg(form.register, 64))
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(c.b, "  store i%d %s, ptr %%%s, align 1\n", form.bits, value, pointer)
	return nil
}
