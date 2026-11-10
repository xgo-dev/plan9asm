package plan9asm

// Only this paired emitter may supply native mathematical values or the
// existing ambient-CW continuations. Other stores still need their original
// logical control-word proof. Backend selection alone supplies no source inputs.
func (c *amd64Ctx) x87HardwareRoundingResultStep(ins Instr, state *x86ResultState,
	owned []bool, resultOffset int64, arch string) (bool, bool) {
	if c.x87Mode == X87Software {
		return false, false
	}
	form, known, err := x86X87ValueProperties(ins, arch)
	if !known || form.spec.kind != x86X87Round && form.spec.kind != x86X87NativeMath &&
		!(form.spec.kind == x86X87IntegerMove && form.spec.width == 'V' && form.spec.pop == 1) {
		return false, false
	}
	if !c.useHardwareX87() {
		return false, false
	}
	if err != nil {
		return false, true
	}
	return x86ResultX87ValueStepWithHardwareRounding(ins, state, owned, resultOffset, arch, true)
}
