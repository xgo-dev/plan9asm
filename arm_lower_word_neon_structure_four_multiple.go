package plan9asm

import "fmt"

type armRawNEONStructureFourMultiple struct {
	load        bool
	elementBits int
	first       int
	stride      int
	base        int
	offset      int
	alignment   int
}

// decodeARMRawNEONStructureFourMultiple covers A32 VLD4/VST4 multiple-
// structure forms in 8-, 16-, and 32-bit elements, with D-register spacing
// one or two, every alignment code, and all post-index addressing modes.
func decodeARMRawNEONStructureFourMultiple(word uint32) (armRawNEONStructureFourMultiple, bool) {
	if word&0xff900000 != 0xf4000000 {
		return armRawNEONStructureFourMultiple{}, false
	}
	typeField := int(word >> 8 & 15)
	if typeField != 0 && typeField != 1 {
		return armRawNEONStructureFourMultiple{}, false
	}
	size := int(word >> 6 & 3)
	if size == 3 {
		return armRawNEONStructureFourMultiple{}, false
	}
	stride := 1 + typeField
	first := int(word>>12)&15 | int(word>>22&1)*16
	if first+3*stride >= 32 {
		return armRawNEONStructureFourMultiple{}, false
	}
	alignmentCode := int(word >> 4 & 3)
	alignment := 0
	if alignmentCode != 0 {
		alignment = 4 << alignmentCode
	}
	return armRawNEONStructureFourMultiple{
		load:        word>>21&1 != 0,
		elementBits: 8 << size,
		first:       first,
		stride:      stride,
		base:        int(word>>16) & 15,
		offset:      int(word) & 15,
		alignment:   alignment,
	}, true
}

func (c *armCtx) lowerRawNEONStructureFourMultiple(form armRawNEONStructureFourMultiple) error {
	if form.base == 15 {
		return fmt.Errorf("arm NEON VLD4/VST4 multiple cannot safely use PC as its base")
	}
	baseReg := Reg(fmt.Sprintf("R%d", form.base))
	base, err := c.loadReg(baseReg)
	if err != nil {
		return err
	}
	elementType := fmt.Sprintf("i%d", form.elementBits)
	elementBytes := form.elementBits / 8
	lanes := 64 / form.elementBits
	for registerIndex := 0; registerIndex < 4; registerIndex++ {
		register := form.first + registerIndex*form.stride
		vector := "poison"
		if !form.load {
			vector, _, err = c.loadARMRawNEONVector(
				register, form.elementBits, false, elementType,
			)
			if err != nil {
				return err
			}
		}
		for lane := 0; lane < lanes; lane++ {
			byteOffset := (lane*4 + registerIndex) * elementBytes
			address := base
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
			if form.load {
				value := c.newTmp()
				updated := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = load %s, ptr %%%s, align %d\n",
					value, elementType, pointer, alignment)
				fmt.Fprintf(c.b, "  %%%s = insertelement <%d x %s> %s, %s %%%s, i32 %d\n",
					updated, lanes, elementType, vector, elementType, value, lane)
				vector = "%" + updated
				continue
			}
			value := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <%d x %s> %s, i32 %d\n",
				value, lanes, elementType, vector, lane)
			fmt.Fprintf(c.b, "  store %s %%%s, ptr %%%s, align %d\n",
				elementType, value, pointer, alignment)
		}
		if form.load {
			if err := c.storeARMRawNEONVector(
				register, form.elementBits, false, elementType, vector,
			); err != nil {
				return err
			}
		}
	}
	if form.offset == 15 {
		return nil
	}
	increment := "32"
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
