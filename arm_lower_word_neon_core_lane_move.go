package plan9asm

import "fmt"

type armRawNEONCoreLaneMove struct {
	toVector    bool
	unsigned    bool
	condition   string
	elementBits int
	lane        int
	vector      int
	core        int
}

// decodeARMRawNEONCoreLaneMove covers A32 VMOV between a core register and a
// D-register element: 8/16/32-bit insertion and signed/unsigned 8/16-bit or
// ordinary 32-bit extraction, with all executable condition and lane fields.
func decodeARMRawNEONCoreLaneMove(word uint32) (armRawNEONCoreLaneMove, bool) {
	const variable = uint32(0xf0fff0e0)
	if word&^variable != 0x0e000b10 {
		return armRawNEONCoreLaneMove{}, false
	}
	condition, ok := armRawCondition(word >> 28)
	if !ok {
		return armRawNEONCoreLaneMove{}, false
	}
	toVector := word>>20&1 == 0
	unsigned := word>>23&1 != 0
	if toVector && unsigned {
		return armRawNEONCoreLaneMove{}, false
	}
	elementBits := 32
	lane := int(word >> 21 & 1)
	if word>>22&1 != 0 {
		elementBits = 8
		lane = int(word>>21&1)*4 | int(word>>6&1)*2 | int(word>>5&1)
	} else if word>>5&1 != 0 {
		elementBits = 16
		lane = int(word>>21&1)*2 | int(word>>6&1)
	} else if word>>6&1 != 0 || unsigned {
		return armRawNEONCoreLaneMove{}, false
	}
	return armRawNEONCoreLaneMove{
		toVector:    toVector,
		unsigned:    unsigned,
		condition:   condition,
		elementBits: elementBits,
		lane:        lane,
		vector:      int(word>>16)&15 | int(word>>7&1)*16,
		core:        int(word >> 12 & 15),
	}, true
}

func (c *armCtx) lowerRawNEONCoreLaneMove(form armRawNEONCoreLaneMove) error {
	if form.core == 15 {
		return fmt.Errorf("arm NEON core/lane VMOV cannot safely use PC")
	}
	if form.condition != "" && form.condition != "AL" {
		condition := form.condition
		form.condition = "AL"
		return c.emitConditionalEffect(condition, func() error {
			return c.lowerRawNEONCoreLaneMove(form)
		})
	}
	elementType := fmt.Sprintf("i%d", form.elementBits)
	coreReg := Reg(fmt.Sprintf("R%d", form.core))
	vector, lanes, err := c.loadARMRawNEONVector(
		form.vector, form.elementBits, false, elementType,
	)
	if err != nil {
		return err
	}
	if form.toVector {
		value, err := c.loadReg(coreReg)
		if err != nil {
			return err
		}
		if form.elementBits != 32 {
			narrow := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to %s\n", narrow, value, elementType)
			value = "%" + narrow
		}
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x %s> %s, %s %s, i32 %d\n",
			result, lanes, elementType, vector, elementType, value, form.lane)
		return c.storeARMRawNEONVector(
			form.vector, form.elementBits, false, elementType, "%"+result,
		)
	}
	extracted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement <%d x %s> %s, i32 %d\n",
		extracted, lanes, elementType, vector, form.lane)
	value := "%" + extracted
	if form.elementBits != 32 {
		extend := "sext"
		if form.unsigned {
			extend = "zext"
		}
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to i32\n", wide, extend, elementType, value)
		value = "%" + wide
	}
	return c.storeReg(coreReg, value)
}
