package plan9asm

type armRawVFPMove struct {
	condition   string
	bits        int
	destination int
	source      int
}

// decodeARMRawVFPMove covers the complete A32 scalar VMOV (register) family:
// every condition and all S0..S31 and D0..D31 source/destination fields. Raw
// single-register moves need a dedicated path because x/arch's Go syntax uses
// F<n> for even S registers and S<n> for odd ones, while source-level Go F
// registers represent a different register view.
func decodeARMRawVFPMove(word uint32) (armRawVFPMove, bool) {
	const mask = uint32(0x0fbf0ed0)
	const base = uint32(0x0eb00a40)
	if word&mask != base {
		return armRawVFPMove{}, false
	}
	condition, ok := armRawCondition(word >> 28)
	if !ok {
		return armRawVFPMove{}, false
	}
	bits := 32
	destination := int(word>>12) & 15
	source := int(word) & 15
	if word>>8&1 != 0 {
		bits = 64
		destination += int(word>>22&1) * 16
		source += int(word>>5&1) * 16
	} else {
		destination = destination*2 + int(word>>22&1)
		source = source*2 + int(word>>5&1)
	}
	return armRawVFPMove{
		condition:   condition,
		bits:        bits,
		destination: destination,
		source:      source,
	}, true
}

func (c *armCtx) lowerRawVFPMove(form armRawVFPMove) error {
	if form.condition != "" && form.condition != "AL" {
		condition := form.condition
		form.condition = "AL"
		return c.emitConditionalEffect(condition, func() error {
			return c.lowerRawVFPMove(form)
		})
	}
	if form.bits == 32 {
		value, err := c.loadARMRawSingleBits(form.source)
		if err != nil {
			return err
		}
		return c.storeARMRawSingleBits(form.destination, value, "")
	}
	value, err := c.loadFReg(armRawVFPBackingReg(form.source, 64))
	if err != nil {
		return err
	}
	return c.storeFReg(armRawVFPBackingReg(form.destination, 64), value)
}
