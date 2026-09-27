package plan9asm

import "fmt"

type arm64RawModifiedImmediate struct {
	op          Op
	arrangement arm64VectorArrangement
	immediate   byte
	value       uint64
	destination int
}

func decodeARM64RawModifiedImmediate(word uint32) (arm64RawModifiedImmediate, bool) {
	// Advanced SIMD modified immediate. Keep the fixed class and o2 bit, while
	// allowing Q, op, cmode, imm8, and Rd to be interpreted below.
	if word&0x9ff80c00 != 0x0f000400 {
		return arm64RawModifiedImmediate{}, false
	}
	opBit := word&(1<<29) != 0
	cmode := int(word>>12) & 15
	immediate := byte(((word >> 16) & 7 << 5) | ((word >> 5) & 31))
	vectorBits := 64
	if word&(1<<30) != 0 {
		vectorBits = 128
	}

	form := arm64RawModifiedImmediate{op: "VMOVI", immediate: immediate, destination: int(word) & 31}
	var value uint64
	if cmode < 12 && cmode&1 != 0 {
		// Odd cmodes are the ORR/BIC modified-immediate family. The same
		// imm8/shift grammar applies to both Q widths and all S/H lanes.
		if cmode < 8 {
			form.arrangement = arm64VectorArrangement{elementBits: 32, lanes: vectorBits / 32}
			value = uint64(uint32(immediate) << uint((cmode-1)/2*8))
		} else {
			form.arrangement = arm64VectorArrangement{elementBits: 16, lanes: vectorBits / 16}
			value = uint64(uint16(immediate) << uint((cmode-9)/2*8))
		}
		form.op = "VORR"
		if opBit {
			form.op = "VBIC"
		}
		form.value = value
		return form, true
	}
	switch cmode {
	case 0, 2, 4, 6:
		form.arrangement = arm64VectorArrangement{elementBits: 32, lanes: vectorBits / 32}
		value = uint64(uint32(immediate) << uint(cmode/2*8))
	case 8, 10:
		form.arrangement = arm64VectorArrangement{elementBits: 16, lanes: vectorBits / 16}
		value = uint64(uint16(immediate) << uint((cmode-8)/2*8))
	case 12:
		form.arrangement = arm64VectorArrangement{elementBits: 32, lanes: vectorBits / 32}
		value = uint64(uint32(immediate)<<8 | 0xff)
	case 13:
		form.arrangement = arm64VectorArrangement{elementBits: 32, lanes: vectorBits / 32}
		value = uint64(uint32(immediate)<<16 | 0xffff)
	case 14:
		if !opBit {
			form.arrangement = arm64VectorArrangement{elementBits: 8, lanes: vectorBits / 8}
			value = uint64(immediate)
			break
		}
		form.arrangement = arm64VectorArrangement{elementBits: 64, lanes: vectorBits / 64}
		for bit := 0; bit < 8; bit++ {
			if immediate&(1<<bit) != 0 {
				value |= uint64(0xff) << (bit * 8)
			}
		}
		form.value = value
		return form, true
	default:
		// cmode 15 encodes floating-point immediates, a neighboring family.
		return arm64RawModifiedImmediate{}, false
	}

	if opBit {
		form.op = "VMVNI"
		switch form.arrangement.elementBits {
		case 16:
			value = uint64(^uint16(value))
		case 32:
			value = uint64(^uint32(value))
		default:
			return arm64RawModifiedImmediate{}, false
		}
	}
	form.value = value
	return form, true
}

func (c *arm64Ctx) lowerRawModifiedImmediate(form arm64RawModifiedImmediate) error {
	destination := Reg(fmt.Sprintf("V%d", form.destination))
	if form.op == "VORR" || form.op == "VBIC" {
		old, err := c.loadARM64VectorInteger(destination, form.arrangement)
		if err != nil {
			return err
		}
		operation := "or"
		value := form.value
		if form.op == "VBIC" {
			operation = "and"
			laneMask := (uint64(1) << uint(form.arrangement.elementBits)) - 1
			value = ^value & laneMask
		}
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s <%d x i%d> %s, %s\n", result, operation,
			form.arrangement.lanes, form.arrangement.elementBits, old,
			arm64VectorIntegerSplat(form.arrangement, int64(value)))
		return c.storeARM64VectorInteger(destination, form.arrangement, "%"+result)
	}
	value := arm64VectorIntegerSplat(form.arrangement, int64(form.value))
	if err := c.storeARM64VectorInteger(destination, form.arrangement, value); err != nil {
		return fmt.Errorf("lower ARM64 raw %s: %w", form.op, err)
	}
	return nil
}
