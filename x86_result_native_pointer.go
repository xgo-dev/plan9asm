package plan9asm

// This domain observes only opaque incoming pointer identities. Copying or
// computing an address does not initialize any numerical bytes or its pointee:
// all native reads remain unproved without an independent caller-memory fact.
// It grants no bounds, noalias, escape, lifetime, frame or translator permission.

func x86ResultPointerWord(arch string) int64 {
	if arch == "386" {
		return 4
	}
	return 8
}

// Select an existing whole-word role, never numerical address bits or memory
// contents. The caller supplies its own independent pointer/provenance domain.
func x86ResultPointerOperand(arg Operand, gp [16]bool, fp map[int64]bool, arch string) bool {
	if arg.Kind == OpFP {
		return fp[arg.FPOffset]
	}
	index, _, valid := x86ResultGP(arg.Reg, x86ResultPointerWord(arch), arch)
	return arg.Kind == OpReg && valid && gp[index]
}

func x86ResultIncomingPointerAddressIdentity(arg Operand, state *x86ResultState, arch string) bool {
	return x86ResultIncomingPointerAddress(arg, state, arch, false)
}

// Only an existing paired native read may commute a numerical base with an
// unscaled pointer index. Stores, RMW, caller certificates and LEA keep the
// original base-pointer entry above; this grants no reusable address fact.
func x86ResultIncomingPointerReadAddressIdentity(arg Operand, state *x86ResultState, arch string) bool {
	return x86ResultIncomingPointerAddress(arg, state, arch, true)
}

func x86ResultIncomingPointerAddress(arg Operand, state *x86ResultState, arch string, commutedRead bool) bool {
	if arg.Kind != OpMem {
		return false
	}
	memory := arg.Mem
	if memory.Sym != "" || memory.OffRaw != "" || memory.Segment != "" || memory.IndexExt != "" ||
		memory.Off < -1<<31 || memory.Off > 1<<31-1 {
		return false
	}
	word := x86ResultPointerWord(arch)
	base, baseMask, valid := x86ResultGP(memory.Base, word, arch)
	if !valid {
		return false
	}
	if memory.Index == "" {
		return memory.Scale == 0 && (state.shapeOnly || state.pointerGP[base])
	}
	if memory.Scale != 1 && memory.Scale != 2 && memory.Scale != 4 && memory.Scale != 8 {
		return false
	}
	index, mask, valid := x86ResultGP(memory.Index, word, arch)
	if !valid {
		return false
	}
	if (state.shapeOnly || state.pointerGP[base]) && state.gp[index]&mask == mask {
		return true // Preserve the existing pointer-base/numerical-index role.
	}
	return commutedRead && !state.shapeOnly && memory.Scale == 1 &&
		!state.pointerGP[base] && state.gp[base]&baseMask == baseMask && state.pointerGP[index]
}

func x86ResultIncomingPointerTransfer(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	word := x86ResultPointerWord(arch)
	move, lea, add, sub := Op("MOVQ"), Op("LEAQ"), Op("ADDQ"), Op("SUBQ")
	if arch == "386" {
		move, lea, add, sub = "MOVL", "LEAL", "ADDL", "SUBL"
	}
	if len(ins.Args) != 2 {
		return false, false
	}
	first, last := ins.Args[0], ins.Args[1]
	writePointer := func() bool {
		if last.Kind != OpReg {
			return false
		}
		index, _, valid := x86ResultGP(last.Reg, word, arch)
		if valid {
			state.pointerGP[index], state.gp[index] = true, 0
			state.canonicalGP[index] = 0
		}
		return valid
	}
	if ins.Op == move {
		if first.Kind == OpFP && state.pointerFP[first.FPOffset] {
			return writePointer(), true
		}
		// The source-wide top state represents numerical and pointer inputs
		// together; a reaching state never carries that union as authority.
		if first.Kind == OpReg && !state.shapeOnly {
			index, _, valid := x86ResultGP(first.Reg, word, arch)
			if valid && state.pointerGP[index] {
				return writePointer(), true
			}
		}
	}
	if ins.Op == lea && first.Kind == OpMem {
		base, _, valid := x86ResultGP(first.Mem.Base, word, arch)
		if valid && (state.shapeOnly || state.pointerGP[base]) {
			address := x86ResultIncomingPointerAddressIdentity(first, state, arch)
			if state.shapeOnly && !address {
				// The source-wide top also represents numerical inputs. A
				// legal NUM-only LEA can have a displacement outside this
				// pointer role (386 uint32, for example). Defer to its typed
				// grammar; reaching pointer identities keep the strict rule.
				return false, false
			}
			return address && writePointer(), true
		}
		// No typed pointer base: let the independent numerical LEA effect
		// prove every actual register input instead of treating it as a pointer.
		return false, false
	}
	if (ins.Op == add || ins.Op == sub) && last.Kind == OpReg {
		index, _, valid := x86ResultGP(last.Reg, word, arch)
		if !valid {
			return false, false
		}
		commuted := !state.pointerGP[index] && ins.Op == add &&
			x86ResultPointerOperand(first, state.pointerGP, state.pointerFP, arch)
		// The shape pass must recognize a declared pointer FP source too.
		// Its top state supplies no reaching identity or numerical permission.
		if !commuted && (!state.pointerGP[index] || state.shapeOnly) {
			return false, false
		}
		number := first
		if commuted {
			if !x86ResultNamedPredicateInstruction(ins) {
				return false, true
			}
			number = last // ADD alone may exchange its pointer and NUM inputs.
		}
		effect, recognized, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
		if !recognized || err != nil || effect.dynamicMemory ||
			!x86ResultRead(number, word, state, owned, arch) {
			return false, true
		}
		if commuted {
			writePointer() // Revoke the old NUM/canonical result, not the source role.
		}
		state.flags = state.flags&^effect.flagsKilled | effect.flagsDefined
		return true, true
	}
	return false, false
}
