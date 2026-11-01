package plan9asm

// Only these two existing branches emit an actual native rounding/conversion
// operation. W/L stores still use the old software lowerer even in Auto mode;
// mode selection cannot invent an ambient-CW continuation for those branches.
// This supplies no numerical representation, memory, entry or FP80 authority.
func (c *amd64Ctx) x87HardwareRoundingResultStep(ins Instr, state *x86ResultState,
	owned []bool, resultOffset int64, arch string) (bool, bool) {
	if !c.useHardwareX87() {
		return false, false
	}
	form, known, err := x86X87ValueProperties(ins, arch)
	if !known || form.spec.kind != x86X87Round &&
		!(form.spec.kind == x86X87IntegerMove && form.spec.width == 'V' && form.spec.pop == 1) {
		return false, false
	}
	if err != nil {
		return false, true
	}
	return x86ResultX87ValueStepWithHardwareRounding(ins, state, owned, resultOffset, arch, true)
}
