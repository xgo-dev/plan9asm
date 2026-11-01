package plan9asm

// x86ResultSwapStep shares the existing Go exchange grammar between result
// observers, but admits only register/register byte effects. Memory exchanges
// still need their independent FP, AUTO, native or caller authority.
func x86ResultSwapStep(ins Instr, state *x86ResultState, arch string) (bool, bool) {
	form, width, known, err := x86SwapProperties(ins, arch)
	if !known {
		return false, false
	}
	if err != nil || form.register.Kind != OpReg || form.other.Kind != OpReg {
		return false, true
	}
	if form.nop {
		return true, true // Preserve even undefined bytes and opaque identities.
	}
	first, firstMask, firstValid := x86ResultGP(form.register.Reg, width, arch)
	last, lastMask, lastValid := x86ResultGP(form.other.Reg, width, arch)
	if !firstValid || !lastValid {
		return false, true
	}
	// Snapshot both required reads before either write. Opaque identities are
	// transferable only at the complete pointer width, never as numeric bytes.
	read := func(index int, mask uint8) (opaque, valid bool) {
		if state.gp[index]&mask == mask {
			return false, true
		}
		return true, width == x86ResultPointerWord(arch) && state.pointerGP[index]
	}
	firstOpaque, firstRead := read(first, firstMask)
	lastOpaque, lastRead := read(last, lastMask)
	if !firstRead || !lastRead {
		return false, true
	}
	write := func(operand Operand, index int, opaque bool) {
		if opaque {
			state.pointerGP[index], state.gp[index] = true, 0
		} else {
			// The register views were validated above; retain the existing
			// partial-write and genuine r32/r64 zero-extension byte effects.
			x86ResultStore(operand, width, state, nil, 0, arch)
		}
	}
	write(form.register, first, lastOpaque)
	write(form.other, last, firstOpaque)
	return true, true // XCHG preserves every flag and all other state domains.
}
