package plan9asm

import (
	"fmt"
	"strconv"
)

type armRawVFPImmediate struct {
	condition   string
	bits        int
	destination int
	immediate   uint8
}

// decodeARMRawVFPImmediate covers the complete A32 VMOV (immediate) family:
// every ordinary ARM condition, both F32/F64 widths, all S0..S31/D0..D31
// destinations, and all 256 encodable floating constants.
func decodeARMRawVFPImmediate(word uint32) (armRawVFPImmediate, bool) {
	const mask = uint32(0x0fb00ef0)
	const base = uint32(0x0eb00a00)
	if word&mask != base {
		return armRawVFPImmediate{}, false
	}
	condition, ok := armRawCondition(word >> 28)
	if !ok {
		return armRawVFPImmediate{}, false
	}
	width := 32
	destination := int(word>>12) & 15
	if word>>8&1 != 0 {
		width = 64
		destination += int(word>>22&1) * 16
	} else {
		destination = destination*2 + int(word>>22&1)
	}
	immediate := uint8(word>>16&15)<<4 | uint8(word&15)
	return armRawVFPImmediate{
		condition:   condition,
		bits:        width,
		destination: destination,
		immediate:   immediate,
	}, true
}

// expandARMVFPImmediate implements the VFPExpandImm operation from the ARM
// architecture. Returning the IEEE bits avoids rounding the encoded constant
// through a host floating-point parser.
func expandARMVFPImmediate(immediate uint8, width int) uint64 {
	exponentBits, fractionBits := 8, 23
	if width == 64 {
		exponentBits, fractionBits = 11, 52
	}
	repeated := uint64(immediate>>6) & 1
	exponent := (repeated ^ 1) << (exponentBits - 1)
	if repeated != 0 {
		exponent |= ((uint64(1) << (exponentBits - 3)) - 1) << 2
	}
	exponent |= uint64(immediate>>4) & 3
	fraction := uint64(immediate&15) << (fractionBits - 4)
	sign := uint64(immediate>>7) << (width - 1)
	return sign | exponent<<fractionBits | fraction
}

func (c *armCtx) lowerRawVFPImmediate(form armRawVFPImmediate) error {
	bits := expandARMVFPImmediate(form.immediate, form.bits)
	if form.bits == 64 {
		return c.selectFRegWrite(
			armRawVFPBackingReg(form.destination, 64),
			form.condition,
			strconv.FormatUint(bits, 10),
		)
	}

	reg := armRawVFPBackingReg(form.destination, 32)
	old, err := c.loadFReg(reg)
	if err != nil {
		return err
	}
	newBits := strconv.FormatUint(bits, 10)
	if form.destination&1 != 0 {
		kept := c.newTmp()
		merged := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, 4294967295\n", kept, old)
		fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %d\n", merged, kept, bits<<32)
		newBits = "%" + merged
	} else {
		kept := c.newTmp()
		merged := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, -4294967296\n", kept, old)
		fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %s\n", merged, kept, newBits)
		newBits = "%" + merged
	}
	return c.selectFRegWrite(reg, form.condition, newBits)
}
