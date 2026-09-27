package plan9asm

import "fmt"

type arm64RawMoveWide struct {
	op          Op
	width       int
	shift       int
	immediate   uint16
	destination int
}

func decodeARM64RawMoveWide(word uint32) (arm64RawMoveWide, bool) {
	if word&0x1f800000 != 0x12800000 {
		return arm64RawMoveWide{}, false
	}
	var op Op
	switch (word >> 29) & 3 {
	case 0:
		op = "MOVN"
	case 2:
		op = "MOVZ"
	case 3:
		op = "MOVK"
	default:
		return arm64RawMoveWide{}, false
	}
	width := 32
	if word&(1<<31) != 0 {
		width = 64
	}
	halfword := int(word>>21) & 3
	if width == 32 && halfword > 1 {
		return arm64RawMoveWide{}, false
	}
	return arm64RawMoveWide{
		op:          op,
		width:       width,
		shift:       halfword * 16,
		immediate:   uint16(word >> 5),
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawMoveWide(form arm64RawMoveWide) error {
	// Rd=31 denotes WZR/XZR for this encoding class.
	if form.destination == 31 {
		return nil
	}
	widthMask := uint64(0xffffffff)
	if form.width == 64 {
		widthMask = ^uint64(0)
	}
	field := uint64(form.immediate) << form.shift
	reg := Reg(fmt.Sprintf("R%d", form.destination))
	switch form.op {
	case "MOVZ":
		return c.storeReg(reg, fmt.Sprintf("%d", field))
	case "MOVN":
		return c.storeReg(reg, fmt.Sprintf("%d", (^field)&widthMask))
	case "MOVK":
		old, err := c.loadReg(reg)
		if err != nil {
			return err
		}
		preserveMask := widthMask & ^(uint64(0xffff) << form.shift)
		preserved := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, %d\n", preserved, old, preserveMask)
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %d\n", result, preserved, field)
		return c.storeReg(reg, "%"+result)
	default:
		return fmt.Errorf("unknown ARM64 raw move-wide operation %s", form.op)
	}
}
