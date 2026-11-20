package plan9asm

import (
	"fmt"
	"math"
)

// A logical FP span is usable only when every byte belongs to a validated
// scalar ABI0 slot. Padding and unknown native caller-frame bytes are not
// synthesized. This is a value/span proof, not a physical alignment proof.
func (c *amd64Ctx) validateX86PackedShiftFPSpan(off int64, width int) error {
	if width <= 0 || off < 0 || off > math.MaxInt64-int64(width) {
		return fmt.Errorf("packed shift FP span is not bounded: %w", ErrProbeNeedsContext)
	}
	if err := c.validateFPVectorSpan(off, width); err != nil {
		return fmt.Errorf("packed shift needs complete FP bytes: %v: %w", err, ErrProbeNeedsContext)
	}
	for byteOffset := off; byteOffset < off+int64(width); byteOffset++ {
		slot, _, _ := c.fpVectorSlot(byteOffset)
		if x86FrameScalarBytes(slot.Type, c.goarch) == 0 {
			return fmt.Errorf("packed shift FP type %s lacks scalar byte storage: %w", slot.Type, ErrProbeNeedsContext)
		}
	}
	return nil
}
