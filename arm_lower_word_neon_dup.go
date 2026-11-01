package plan9asm

import "fmt"

type armRawNEONDup struct {
	condition   string
	elementBits int
	destination int
	core        int
	quad        bool
}

// decodeARMRawNEONDup covers the complete A32 VDUP (ARM core register)
// family for 8-, 16-, and 32-bit elements and both D and Q destinations.
func decodeARMRawNEONDup(word uint32) (armRawNEONDup, bool) {
	if word&0x0f900f5f != 0x0e800b10 {
		return armRawNEONDup{}, false
	}
	condition, ok := armRawCondition(word >> 28)
	if !ok {
		return armRawNEONDup{}, false
	}
	bit8 := word>>22&1 != 0
	bit16 := word>>5&1 != 0
	if bit8 && bit16 {
		return armRawNEONDup{}, false
	}
	elementBits := 32
	if bit8 {
		elementBits = 8
	} else if bit16 {
		elementBits = 16
	}
	destination := int(word>>16)&15 | int(word>>7&1)*16
	quad := word>>21&1 != 0
	if quad && destination&1 != 0 {
		return armRawNEONDup{}, false
	}
	return armRawNEONDup{
		condition:   condition,
		elementBits: elementBits,
		destination: destination,
		core:        int(word>>12) & 15,
		quad:        quad,
	}, true
}

func (c *armCtx) lowerRawNEONDup(form armRawNEONDup) error {
	if form.core == 15 {
		return fmt.Errorf("arm NEON VDUP cannot safely use PC")
	}
	if form.condition != "" && form.condition != "AL" {
		condition := form.condition
		form.condition = "AL"
		return c.emitConditionalEffect(condition, func() error {
			return c.lowerRawNEONDup(form)
		})
	}
	source, err := c.loadReg(Reg(fmt.Sprintf("R%d", form.core)))
	if err != nil {
		return err
	}
	element := source
	if form.elementBits != 32 {
		narrow := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to i%d\n", narrow, source, form.elementBits)
		element = "%" + narrow
	}
	lanes := 64 / form.elementBits
	inserted := c.newTmp()
	broadcast := c.newTmp()
	bits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> poison, i%d %s, i32 0\n", inserted, lanes, form.elementBits, form.elementBits, element)
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i%d> %%%s, <%d x i%d> poison, <%d x i32> zeroinitializer\n", broadcast, lanes, form.elementBits, inserted, lanes, form.elementBits, lanes)
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %%%s to i64\n", bits, lanes, form.elementBits, broadcast)
	if err := c.storeFReg(armRawVFPBackingReg(form.destination, 64), "%"+bits); err != nil {
		return err
	}
	if form.quad {
		return c.storeFReg(armRawVFPBackingReg(form.destination+1, 64), "%"+bits)
	}
	return nil
}
