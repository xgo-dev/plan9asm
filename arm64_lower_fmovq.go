package plan9asm

import "fmt"

// loadFMOVQFrame reconstructs the 16 contiguous bytes addressed by off(FP)
// from the scalar LLVM fields used to model Go aggregate parameters.
func (c *arm64Ctx) loadFMOVQFrame(off int64) (string, error) {
	packed := "0"
	for cursor := off; cursor < off+16; {
		slot, ok := c.fpParams[cursor]
		if !ok {
			return "", fmt.Errorf("arm64: FMOVQ input frame range +%d(FP)..+%d(FP) has no slot at +%d(FP)", off, off+16, cursor)
		}
		size := frameTypeSize(slot.Type, 8)
		if size <= 0 || size > 8 || cursor+size > off+16 {
			return "", fmt.Errorf("arm64: FMOVQ input frame slot +%d(FP) has unsupported type %q", cursor, slot.Type)
		}
		value, err := c.evalFPValue64(Operand{Kind: OpFP, FPOffset: cursor})
		if err != nil {
			return "", err
		}
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i64 %s to i128\n", wide, value)
		part := "%" + wide
		if shift := (cursor - off) * 8; shift != 0 {
			shifted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shl i128 %s, %d\n", shifted, part, shift)
			part = "%" + shifted
		}
		merged := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i128 %s, %s\n", merged, packed, part)
		packed = "%" + merged
		cursor += size
	}
	vector := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast i128 %s to <16 x i8>\n", vector, packed)
	return "%" + vector, nil
}

// storeFMOVQFrame splits a vector into the scalar LLVM result slots that cover
// the 16 contiguous bytes addressed by off(FP).
func (c *arm64Ctx) storeFMOVQFrame(off int64, value string) error {
	packed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to i128\n", packed, value)
	for cursor := off; cursor < off+16; {
		slot, ok := c.fpResultSlotByOffset(cursor)
		if !ok {
			return fmt.Errorf("arm64: FMOVQ output frame range +%d(FP)..+%d(FP) has no slot at +%d(FP)", off, off+16, cursor)
		}
		size := frameTypeSize(slot.Type, 8)
		if size <= 0 || size > 8 || cursor+size > off+16 {
			return fmt.Errorf("arm64: FMOVQ output frame slot +%d(FP) has unsupported type %q", cursor, slot.Type)
		}
		part := "%" + packed
		if shift := (cursor - off) * 8; shift != 0 {
			shifted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = lshr i128 %s, %d\n", shifted, part, shift)
			part = "%" + shifted
		}
		narrow := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i128 %s to i64\n", narrow, part)
		if err := c.storeFPResult64(cursor, "%"+narrow); err != nil {
			return err
		}
		cursor += size
	}
	return nil
}
