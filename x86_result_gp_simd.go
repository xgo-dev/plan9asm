package plan9asm

import "strings"

// Both result observers consume the same typed numerical transfer. The public
// observer enters only for register/register operands; the private observer
// retains its existing logical-memory roles. Neither acquires native backing,
// caller permission or numerical pointer bytes.
func x86ResultGPSIMDTransfer(ins Instr, form x86GPSIMDTransferForm, state *x86ResultState,
	owned []bool, resultOffset int64, arch string) bool {
	return x86ResultGPSIMDTransferWithNativeMemory(ins, form, state, owned, resultOffset, arch, false)
}

func x86ResultGPSIMDTransferWithNativeMemory(ins Instr, form x86GPSIMDTransferForm, state *x86ResultState,
	owned []bool, resultOffset int64, arch string, nativeMemory bool) bool {
	if form.mmx || form.spec.rawOnly {
		return false
	}
	width := int64(form.bits / 8)
	lowMask := uint16(1)<<uint(width) - 1
	var known uint16
	if form.sourceX {
		index, valid := amd64ParseXReg(ins.Args[0].Reg)
		if !valid {
			return false
		}
		known = state.xmm[index] & lowMask
	} else if ins.Args[0].Kind == OpReg {
		index, mask, valid := x86ResultGP(ins.Args[0].Reg, width, arch)
		if !valid || !state.shapeOnly && (state.pointerGP[index] || state.callerAddressGP[index]) {
			return false // Opaque addresses are not numerical GP inputs.
		}
		known = uint16(state.gp[index] & mask)
	} else if !x86ResultReadWithNativeContinuation(ins, ins.Args[0], width, state, owned, arch, nativeMemory) {
		return false
	} else {
		known = lowMask // Memory still needs its complete independent read role.
	}
	if form.destinationX {
		index, valid := amd64ParseXReg(ins.Args[1].Reg)
		if !valid {
			return false
		}
		state.writeVector(index, 16,
			form.definedVectorBytes(uint64(known), state.vectorBytes(index)), form.spec.legacy)
		return true
	}
	if ins.Args[1].Kind == OpReg {
		index, _, valid := x86ResultGP(ins.Args[1].Reg, width, arch)
		if !valid {
			return false
		}
		// The active GP bytes replace old facts, even when unknown. A dword
		// write clears AMD64's upper dword; mode32 has no qword GP read role.
		state.gp[index] = uint8(known) | ^uint8(lowMask)
		state.pointerGP[index], state.callerAddressGP[index] = false, false
		state.canonicalGP[index] = 0 // Numerical dependencies do not prove 0/1.
		return true
	}
	if known != lowMask {
		return false // A stored unknown byte cannot initialize FP/AUTO/SB data.
	}
	if nativeMemory && form.memoryWrite && x86ResultNamedPredicateInstruction(ins) &&
		ins.x86NumericalRead == nil && x86OrdinaryNativeMemoryOperand(ins.Args[1], arch) &&
		x86ResultIncomingPointerAddressIdentity(ins.Args[1], state, arch) {
		return true // The paired exact volatile store creates no reusable memory facts.
	}
	if form.memoryWrite && ins.Args[1].Kind == OpSym {
		// Only the existing private memory consumer enters this branch.
		// An ordinary SB store defines no FP result bytes and supplies no
		// address or extent certificate.
		symbol := strings.TrimSpace(ins.Args[1].Sym)
		base, _, valid := parseSBRef(symbol)
		return valid && strings.HasSuffix(symbol, "(SB)") &&
			strings.IndexAny(base, "$+(),[] \t") < 0
	}
	return x86ResultStore(ins.Args[1], width, state, owned, resultOffset, arch)
}
