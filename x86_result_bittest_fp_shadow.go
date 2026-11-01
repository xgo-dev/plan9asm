package plan9asm

// The existing BIT emitter reads and, for BTC/BTR/BTS, updates these exact
// logical shadow bytes. Only immediate indexes have a fixed FP envelope.
// Reuse its complete span and numerical effects, not native caller storage.
func (c *amd64Ctx) scalarBitTestFPShadowTransfer(ins Instr, state *x86ResultState,
	owned []bool, arch string) (bool, bool) {
	form, known, err := x86BitTestProperties(ins.Op, ins, arch)
	if !known || err != nil || form.destination.Kind != OpFP || form.index.Kind != OpImm {
		return false, false
	}
	if ins.x86Encoded || ins.x86SourceRaw != nil || ins.x86RawNearReturn != nil ||
		ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 {
		return false, true
	}
	if _, err := c.bitTestFPSpan(form.destination.FPOffset, form.bits/8); err != nil {
		return false, true
	}
	next := state.clone()
	if !x86ResultTransfer(ins, &next, owned, 0, arch) {
		return false, true
	}
	*state = next
	return true, true
}
