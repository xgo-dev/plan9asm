package plan9asm

import "strings"

// Only this module's actual writable numeric bytes supply the memory input
// to the paired XADD/XCHG emitter. Symbol syntax, opaque pointer data and a
// declaration alone cannot supply storage or numerical register outputs.
func (c *amd64Ctx) scalarStaticExchangeTransfer(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	name := Op(strings.ToUpper(string(ins.Op)))
	spec, known := amd64ExchangeSpecs[name]
	if !known {
		return false, false
	}
	symbolic := false
	for _, operand := range ins.Args {
		if operand.Kind == OpSym || operand.Kind == OpMem && operand.Mem.Sym != "" {
			symbolic = true
			break
		}
	}
	if !symbolic {
		return false, false // Cost query only; ordinary native/register forms keep their existing parser.
	}
	form, err := parseAMD64ExchangeForm(arch, name, spec, ins)
	if err != nil {
		return false, true
	}
	address, static := x86StaticSBReadAddress(form.other, arch)
	if !static {
		return false, false // The native pointer, register and physical frame routes keep their own inputs.
	}
	values := c.fpStaticAddressValues
	if !x86ResultNamedPredicateInstruction(ins) || ins.x86NumericalRead != nil ||
		values == nil || state == nil || c.resolve == nil {
		return false, true
	}
	width := int64(spec.bits / 8)
	symbol := resolveAssemblyDataSymbol(address.symbol, c.resolve)
	index, _, valid := x86ResultGP(form.register.Reg, width, arch)
	if !values.objects[symbol] || !values.writable[symbol] || c.fpScalarData[address] < width ||
		!valid || state.pointerGP[index] || !x86ResultRead(form.register, width, state, owned, arch) {
		return false, true
	}
	return x86ResultExchangeWriteback(spec, []Operand{form.register}, state, owned, arch), true
}

// Consume only the actual emitted module's numeric storage and address values.
// The complete shared scalar grammar owns widths, byte views and FLAGS effects;
// the unchanged emitter owns paired volatile accesses. No external symbol or
// declaration-only query gains storage, address or initialized-result facts.
func (c *amd64Ctx) scalarStaticRMWTransfer(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	form, known, err := x86LockScalarRMWProperties(ins.Op, ins, arch)
	if !known || err != nil ||
		!x86ResultNamedPredicateInstruction(ins) || ins.x86NumericalRead != nil {
		return false, false
	}
	if form.spec.bitString {
		return c.scalarStaticBitStringTransfer(form, state, owned, arch)
	}
	destination, static := x86StaticSBReadAddress(form.destination, arch)
	relocation := x86AbsoluteRelocationSource(form.source, arch, form.spec.bits)
	if !static && (!relocation || form.destination.Kind != OpReg) {
		return false, false
	}
	values := c.fpStaticAddressValues
	if values == nil || state == nil {
		return false, true
	}
	width := int64(form.spec.bits / 8)
	if static {
		name := resolveAssemblyDataSymbol(destination.symbol, c.resolve)
		if !values.writable[name] || c.fpScalarData[destination] < width {
			return false, true // A numeric extent alone is not writable storage.
		}
	} else if !x86ResultRead(form.destination, width, state, owned, arch) {
		return false, true
	}
	if relocation {
		address, immediate, valid := x86StaticAddressValueSource(form.source, arch)
		if !valid || !immediate || !values.objects[resolveAssemblyDataSymbol(address.symbol, c.resolve)] {
			return false, true
		}
	} else if !form.spec.unary && !x86ResultRead(form.source, width, state, owned, arch) {
		return false, true
	}
	if (form.spec.stem == "ADC" || form.spec.stem == "SBB") && state.flags&x86ByteFlagCF == 0 {
		return false, true
	}
	if !static {
		index, _, valid := x86ResultGP(form.destination.Reg, width, arch)
		if !valid || state.pointerGP[index] || !x86ResultStore(form.destination, width, state, owned, 0, arch) {
			return false, true
		}
		// Relocation arithmetic is mode32/L only. Its full numerical result
		// and architectural upper zeroes are not a canonical bool or pointer.
		state.canonicalGP[index] = 0xf0
		state.callerAddressGP[index], state.callerAddressOrigin[index] = false, 0
		state.resultAddressGP[index] = x86ResultSlotAddress{}
		if state.boolFrameGP != nil {
			state.boolFrameGP[index] = x86ResultSlotAddress{}
		}
	}
	state.flags = state.flags&^form.spec.flagsKilled | form.spec.flagsDefined
	return true, true // No new memory-read capability or unrelated state escapes.
}

// Both native emitters retain the complete BTC/BTR/BTS memory effect: the LOCK
// helper, or the ordinary emitter's volatile access and signed word selection.
// The actual module owns this writable base word; this is not a bound on the
// register-indexed access. If native execution continues, only its FLAGS result
// becomes numerical. No dynamic extent or reusable memory fact is exported.
func (c *amd64Ctx) scalarStaticBitStringTransfer(form x86LockScalarRMWForm, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	destination, static := x86StaticSBReadAddress(form.destination, arch)
	if !static {
		return false, false
	}
	values := c.fpStaticAddressValues
	if values == nil || state == nil {
		return false, true
	}
	name := resolveAssemblyDataSymbol(destination.symbol, c.resolve)
	width := int64(form.spec.bits / 8)
	if !values.objects[name] || !values.writable[name] || c.fpScalarData[destination] < width ||
		!x86ResultRead(form.source, width, state, owned, arch) {
		return false, true
	}
	state.flags = state.flags&^form.spec.flagsKilled | form.spec.flagsDefined
	return true, true
}
