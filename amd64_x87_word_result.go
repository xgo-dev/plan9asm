package plan9asm

// Auto/Hardware FSTCW emits an actual sideeffect FNSTCW output to the same
// private i16 control slot before reading it. Only this paired lowering check
// may consume that capture; a standalone declaration/availability query cannot
// infer ambient control from the implementation alloca's initial 0x037f.
func (c *amd64Ctx) x87HardwareControlResultStep(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	form, known, err := x86X87WordProperties(ins, arch)
	if !known || form.kind != x86X87StoreControl || c.x87Mode == X87Software {
		return false, false
	}
	if err != nil || !x86ResultNamedPredicateInstruction(ins) || state.x87 == nil || state.x87.word == nil {
		return false, true
	}
	next := state.clone()
	next.x87.word.control = 0xffff
	accepted, _ := x86ResultX87WordStep(ins, &next, owned, resultOffset, arch)
	if accepted {
		*state = next
	}
	return accepted, true
}
