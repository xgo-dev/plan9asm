package plan9asm

import "fmt"

// armRawNEONStructureOne describes the A32 Advanced SIMD VLD1/VST1
// "multiple single elements" encoding. Each transfer moves one to four
// consecutive 64-bit D registers without interleaving their elements.
type armRawNEONStructureOne struct {
	load        bool
	base        int
	offset      int
	first       int
	count       int
	elementBits int
	alignment   int
}

// decodeARMRawNEONStructureOne covers every VLD1/VST1 multiple-single-element
// form described by LLVM's ARMInstrNEON.td VLD1D/VLD1Q/VLD1D3/VLD1D4 and the
// corresponding VST1 classes. offset 15 means no writeback; offset 13 selects
// fixed writeback by the transfer size; every other value is a register
// post-index.
func decodeARMRawNEONStructureOne(word uint32) (armRawNEONStructureOne, bool) {
	// 11110100 D L 0 Rn Vd type size align Rm
	if word&0xff900000 != 0xf4000000 {
		return armRawNEONStructureOne{}, false
	}

	typeField := int(word>>8) & 15
	count := 0
	maxAlignmentCode := 0
	switch typeField {
	case 0b0111:
		count = 1
		maxAlignmentCode = 1 // omitted or 64-bit
	case 0b1010:
		count = 2
		maxAlignmentCode = 2 // omitted, 64-bit, or 128-bit
	case 0b0110:
		count = 3
		maxAlignmentCode = 1 // omitted or 64-bit
	case 0b0010:
		count = 4
		maxAlignmentCode = 3 // omitted, 64-, 128-, or 256-bit
	default:
		return armRawNEONStructureOne{}, false
	}

	alignmentCode := int(word>>4) & 3
	if alignmentCode > maxAlignmentCode {
		return armRawNEONStructureOne{}, false
	}
	first := int(word>>12)&15 | int(word>>22&1)*16
	if first+count > 32 {
		return armRawNEONStructureOne{}, false
	}
	alignment := 0
	if alignmentCode != 0 {
		alignment = 4 << alignmentCode // 1,2,3 encode 8,16,32 bytes.
	}
	return armRawNEONStructureOne{
		load:        word>>21&1 != 0,
		base:        int(word>>16) & 15,
		offset:      int(word) & 15,
		first:       first,
		count:       count,
		elementBits: 8 << (word >> 6 & 3),
		alignment:   alignment,
	}, true
}

func (c *armCtx) lowerRawNEONStructureOne(form armRawNEONStructureOne) error {
	if form.base == 15 {
		return fmt.Errorf("arm NEON VLD1/VST1 cannot safely use PC as its base")
	}
	baseReg := Reg(fmt.Sprintf("R%d", form.base))
	base, err := c.loadReg(baseReg)
	if err != nil {
		return err
	}
	alignment := form.alignment
	if alignment == 0 {
		alignment = 1
	}
	for i := 0; i < form.count; i++ {
		address := base
		if offset := i * 8; offset != 0 {
			adjusted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i32 %s, %d\n", adjusted, base, offset)
			address = "%" + adjusted
		}
		pointer := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i32 %s to ptr\n", pointer, address)
		register := armRawVFPBackingReg(form.first+i, 64)
		if form.load {
			value := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load i64, ptr %%%s, align %d\n", value, pointer, alignment)
			if err := c.storeFReg(register, "%"+value); err != nil {
				return err
			}
			continue
		}
		value, err := c.loadFReg(register)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store i64 %s, ptr %%%s, align %d\n", value, pointer, alignment)
	}

	if form.offset == 15 {
		return nil
	}
	increment := ""
	if form.offset == 13 {
		increment = fmt.Sprintf("%d", form.count*8)
	} else {
		increment, err = c.loadReg(Reg(fmt.Sprintf("R%d", form.offset)))
		if err != nil {
			return err
		}
	}
	updated := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i32 %s, %s\n", updated, base, increment)
	return c.storeReg(baseReg, "%"+updated)
}
