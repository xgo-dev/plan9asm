package plan9asm

// Cost routing only. The complete source proof and the existing move grammar
// still decide initialization, typed storage, masks and native alignment.
func x86LogicalPackedFPStoreBytes(ins Instr, arch string) int64 {
	if form, known, err := amd64PackedVectorMoveProperties(ins, arch); known {
		if err == nil && form.memoryWrite && ins.Args[form.destination].Kind == OpFP {
			return int64(form.byteWidth)
		}
		return 0
	}
	if form, known, err := x86LegacyPackedMoveProperties(ins.Op, ins, arch); known && err == nil &&
		form.memoryWrite && form.destination.Kind == OpFP {
		return 16
	}
	return 0
}

// The emitter already scatters these stores into private logical parameter and
// result fields. Account for the same writes without treating a parameter copy
// as caller storage. Every touched byte must be a unique numeric field, never a
// pointer, bool, hole or TEXT allocation padding. Aligned forms stay separate.
func (c *amd64Ctx) scalarPackedLogicalFPWriteTransfer(ins Instr, state *x86ResultState,
	owned []bool, arch string) (bool, bool) {
	width := x86LogicalPackedFPStoreBytes(ins, arch)
	if width == 0 {
		return false, false
	}
	offset := ins.Args[len(ins.Args)-1].FPOffset
	if offset < 0 || offset > 4096-width {
		return false, true
	}
	for position := int64(0); position < width; position += 8 {
		if _, err := c.scalarFPSpan(offset+position, 64); err != nil {
			return false, true
		}
	}
	if form, known, err := amd64PackedVectorMoveProperties(ins, arch); known {
		return err == nil && x86ResultPackedVectorMoveTransfer(ins, form, state, owned, 0, arch, false), true
	}
	form, _, err := x86LegacyPackedMoveProperties(ins.Op, ins, arch)
	return err == nil && !form.aligned && x86ResultTransfer(ins, state, owned, 0, arch), true
}
