package plan9asm

import "fmt"

type armRawNEONStructureLane struct {
	load        bool
	elementBits int
	lane        int
	first       int
	stride      int
	base        int
	offset      int
	alignment   int
}

// decodeARMRawNEONStructureFourLane covers A32 VLD4/VST4 one-lane forms for
// 8-, 16-, and 32-bit elements, including register spacing, all legal lane
// and alignment fields, and no/fixed/register post-index addressing.
func decodeARMRawNEONStructureFourLane(word uint32) (armRawNEONStructureLane, bool) {
	if word&0xff900000 != 0xf4800000 {
		return armRawNEONStructureLane{}, false
	}
	form := armRawNEONStructureLane{
		load:   word>>21&1 != 0,
		first:  int(word>>12)&15 | int(word>>22&1)*16,
		stride: 1,
		base:   int(word>>16) & 15,
		offset: int(word) & 15,
	}
	switch word >> 8 & 15 {
	case 3:
		form.elementBits = 8
		form.lane = int(word >> 5 & 7)
		if word>>4&1 != 0 {
			form.alignment = 4
		}
	case 7:
		form.elementBits = 16
		form.lane = int(word >> 6 & 3)
		if word>>5&1 != 0 {
			form.stride = 2
		}
		if word>>4&1 != 0 {
			form.alignment = 8
		}
	case 11:
		form.elementBits = 32
		form.lane = int(word >> 7 & 1)
		if word>>6&1 != 0 {
			form.stride = 2
		}
		switch word >> 4 & 3 {
		case 0:
		case 1:
			form.alignment = 8
		case 2:
			form.alignment = 16
		default:
			return armRawNEONStructureLane{}, false
		}
	default:
		return armRawNEONStructureLane{}, false
	}
	if form.first+3*form.stride >= 32 {
		return armRawNEONStructureLane{}, false
	}
	return form, true
}

func (c *armCtx) lowerRawNEONStructureFourLane(form armRawNEONStructureLane) error {
	return c.lowerRawNEONStructureLane(form, 4)
}

func (c *armCtx) lowerRawNEONStructureLane(form armRawNEONStructureLane, count int) error {
	if form.base == 15 {
		return fmt.Errorf("arm NEON VLD4/VST4 lane cannot safely use PC as its base")
	}
	baseReg := Reg(fmt.Sprintf("R%d", form.base))
	base, err := c.loadReg(baseReg)
	if err != nil {
		return err
	}
	elementType := fmt.Sprintf("i%d", form.elementBits)
	elementBytes := form.elementBits / 8
	for index := 0; index < count; index++ {
		address := base
		byteOffset := index * elementBytes
		if byteOffset != 0 {
			adjusted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i32 %s, %d\n", adjusted, base, byteOffset)
			address = "%" + adjusted
		}
		pointer := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i32 %s to ptr\n", pointer, address)
		alignment := form.alignment
		if alignment == 0 {
			alignment = 1
		}
		for alignment > 1 && byteOffset%alignment != 0 {
			alignment /= 2
		}
		register := form.first + index*form.stride
		vector, lanes, err := c.loadARMRawNEONVector(register, form.elementBits, false, elementType)
		if err != nil {
			return err
		}
		if form.load {
			value := c.newTmp()
			updated := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load %s, ptr %%%s, align %d\n", value, elementType, pointer, alignment)
			fmt.Fprintf(c.b, "  %%%s = insertelement <%d x %s> %s, %s %%%s, i32 %d\n",
				updated, lanes, elementType, vector, elementType, value, form.lane)
			if err := c.storeARMRawNEONVector(
				register, form.elementBits, false, elementType, "%"+updated,
			); err != nil {
				return err
			}
			continue
		}
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x %s> %s, i32 %d\n",
			value, lanes, elementType, vector, form.lane)
		fmt.Fprintf(c.b, "  store %s %%%s, ptr %%%s, align %d\n",
			elementType, value, pointer, alignment)
	}
	if form.offset == 15 {
		return nil
	}
	increment := fmt.Sprintf("%d", count*elementBytes)
	if form.offset != 13 {
		increment, err = c.loadReg(Reg(fmt.Sprintf("R%d", form.offset)))
		if err != nil {
			return err
		}
	}
	updated := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i32 %s, %s\n", updated, base, increment)
	return c.storeReg(baseReg, "%"+updated)
}
