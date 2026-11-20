package plan9asm

import (
	"fmt"
	"math"
)

// A narrow lane's FP bytes are independent logical numeric fields. This is
// neither physical frame backing nor a pointer/padding permission. Unlike
// native memory, these separately allocated fields cannot be read as a wide
// first-slot load. Every new narrow view also consumes the whole-source proof.
func (c *amd64Ctx) scalarLaneFPSpan(off int64, bits int) error {
	if bits == 32 || bits == 64 {
		_, err := c.scalarFPSpan(off, bits)
		return err
	}
	fail := func() error {
		return fmt.Errorf("%w: scalar-lane FP byte span +%d/%d lacks complete numeric fields", ErrProbeNeedsContext, off, bits)
	}
	if bits != 8 && bits != 16 || off < 0 || off > math.MaxInt64-int64(bits/8) {
		return fail()
	}
	for current := off; current < off+int64(bits/8); current++ {
		matches := 0
		for _, slots := range [][]FrameSlot{c.sig.Frame.Params, c.fpResults} {
			for _, slot := range slots {
				width := x86FrameTypeSize(slot.Type)
				if width <= 0 || slot.Offset < 0 || slot.Offset > math.MaxInt64-width {
					return fail()
				}
				if current >= slot.Offset && current < slot.Offset+width {
					if slot.Type != I8 && slot.Type != I16 && slot.Type != I32 && slot.Type != I64 && slot.Type != "float" && slot.Type != "double" {
						return fail()
					}
					matches++
				}
			}
		}
		if matches != 1 {
			return fail()
		}
	}
	return nil
}

func (c *amd64Ctx) loadScalarLaneFPBits(off int64, bits int) (string, error) {
	if bits >= 32 {
		return c.loadScalarFPBits(off, bits)
	}
	if err := c.scalarLaneFPSpan(off, bits); err != nil {
		return "", err
	}
	if err := c.scalarFPResultInitialized(); err != nil {
		return "", err
	}
	bytes, err := c.loadFPVectorBytes(off, bits/8)
	if err != nil {
		return "", err
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to i%d\n", value, bits/8, bytes, bits)
	return "%" + value, nil
}

func (c *amd64Ctx) storeScalarLaneFPBits(off int64, bits int, value string) error {
	if bits >= 32 {
		return c.storeScalarFPBits(off, bits, value)
	}
	if err := c.scalarLaneFPSpan(off, bits); err != nil {
		return err
	}
	if err := c.scalarFPResultInitialized(); err != nil {
		return err
	}
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast i%d %s to <%d x i8>\n", bytes, bits, value, bits/8)
	return c.storeFPVectorBytes(off, bits/8, "%"+bytes, "")
}
