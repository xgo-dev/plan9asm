package plan9asm

// Symbol syntax and the shared GP MOV row are separate from storage authority.
// Reuse the register/immediate grammar and its encoded-value normalization;
// the temporary AX address validates only that row and never becomes a source
// operand, initialized address, or permission in either returned form.
func x86ScalarStaticStoreProperties(op Op, ins Instr, arch string) (x86ScalarNativeStoreForm, bool, error) {
	if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg && ins.Args[0].Kind != OpImm {
		return x86ScalarNativeStoreForm{}, false, nil
	}
	if _, valid := x86StaticSBSourceAddress(ins.Args[1], arch); !valid {
		return x86ScalarNativeStoreForm{}, false, nil
	}
	projected := ins
	projected.Args = []Operand{ins.Args[0], {Kind: OpMem, Mem: MemRef{Base: AX}}}
	form, known, err := x86ScalarNativeStoreProperties(op, projected, arch)
	if known && err == nil {
		form.destination = ins.Args[1]
	}
	return form, known, err
}

// Only the emitted module's complete numeric extent and actual writable
// object supply this continuation. A source-level symbol, C declaration,
// pointer value, raw instruction or standalone byte query supplies neither.
// A store defines no register, caller byte, reusable address or memory fact.
func (c *amd64Ctx) scalarStaticMoveTransfer(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	form, known, err := x86ScalarStaticStoreProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) || ins.x86NumericalRead != nil ||
		state == nil || c.fpStaticAddressValues == nil || c.resolve == nil {
		return false, true
	}
	address, valid := x86StaticSBReadAddress(form.destination, arch)
	if !valid || c.fpScalarData[address] < form.bytes {
		return false, true
	}
	name := resolveAssemblyDataSymbol(address.symbol, c.resolve)
	if !c.fpStaticAddressValues.objects[name] || !c.fpStaticAddressValues.writable[name] {
		return false, true // Numeric extent alone does not establish a writable backing object.
	}
	if form.source.Kind == OpReg {
		index, _, valid := x86ResultGP(form.source.Reg, form.bytes, arch)
		if !valid || state.pointerGP[index] {
			return false, true
		}
	}
	return x86ResultRead(form.source, form.bytes, state, owned, arch), true
}
