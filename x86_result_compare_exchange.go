package plan9asm

import "reflect"

// These are source ordinals of complete, same-block prefix/body pairs. This
// is not an inert LOCK effect or a memory capability. The following opcode
// still needs its own independent reaching input/result transfer.
func x86ResultSourceLockPrefixes(fn Func, arch string) map[int]Instr {
	bound := make(map[int]Instr)
	if fn.x86DirectTailRoot != nil {
		return bound // A one-node continuation block cannot borrow source adjacency.
	}
	var ordinals []int
	for ordinal, ins := range fn.Instrs {
		if ins.Op != OpLABEL {
			ordinals = append(ordinals, ordinal)
		}
	}
	context := amd64Ctx{goarch: arch, blocks: amd64SplitBlocks(fn)}
	at := 0
	for bi, block := range context.blocks {
		for ii, ins := range block.instrs {
			if at >= len(ordinals) || !reflect.DeepEqual(ins, fn.Instrs[ordinals[at]]) {
				return nil
			}
			if ins.Op == "LOCK" && x86ResultNamedPredicateInstruction(ins) && ii+1 < len(block.instrs) &&
				x86ResultNamedPredicateInstruction(block.instrs[ii+1]) && context.namedLockPrefixBinding(bi, ii, ins) == nil {
				bound[ordinals[at]] = ins
			}
			at++
		}
	}
	if at != len(ordinals) {
		return nil
	}
	return bound
}

func x86CompareExchangeResultOutputs(form x86CompareExchangeForm) (int64, []Reg) {
	width, outputs := int64(form.spec.bits/8), []Reg{AX}
	if form.spec.pair {
		return width / 2, append(outputs, DX)
	}
	if form.destination.Kind == OpReg {
		outputs = append(outputs, form.destination.Reg)
	}
	return width, outputs
}

// This is only the numerical continuation of the already paired native CAS
// emitter. It supplies neither a readable pointee nor reusable write/extent,
// native-entry, alignment, frame or caller permission. The original complete
// sideeffect opcode still performs its read/write cycle, faults and ordering.
func x86LoweredCompareExchangeResultStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	return x86LoweredCompareExchangeResultStepWithAddressBits(ins, state, owned, arch, false)
}

// The existing closed-leaf address-bit scope permits one complete actual
// caller word as a CAS value, never as NUM or a new memory/GC certificate.
func x86LoweredCompareExchangeResultStepWithAddressBits(ins Instr, state *x86ResultState, owned []bool,
	arch string, addressBits bool) (bool, bool) {
	form, known, err := x86CompareExchangeProperties(ins.Op, ins, arch)
	if !known {
		return false, false
	}
	if err != nil || !x86ResultNamedPredicateInstruction(ins) {
		return false, true
	}
	width, outputs := x86CompareExchangeResultOutputs(form)
	read := func(operand Operand) (numeric, valid bool) {
		if x86ResultRead(operand, width, state, owned, arch) {
			return true, true
		}
		if !addressBits || width != x86ResultPointerWord(arch) || operand.Kind != OpReg ||
			x86LogicalSourceFrameRegister(operand.Reg, arch) {
			return false, false
		}
		root, _, valid := x86ResultGP(operand.Reg, width, arch)
		return false, valid && state.pointerGP[root] && state.callerAddressGP[root]
	}
	inputs := []Operand{form.source, {Kind: OpReg, Reg: AX}}
	if form.spec.pair {
		inputs = []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: DX}, {Kind: OpReg, Reg: BX}, {Kind: OpReg, Reg: CX}}
	}
	for _, operand := range inputs {
		if _, valid := read(operand); !valid {
			return false, true
		}
	}
	var numericOutputs [2]bool
	for index, reg := range outputs {
		numericOutputs[index] = x86ResultRead(Operand{Kind: OpReg, Reg: reg}, width, state, owned, arch)
	}
	if form.destination.Kind == OpReg {
		destinationNumeric, valid := read(form.destination)
		if !valid {
			return false, true
		}
		sourceNumeric, _ := read(form.source)
		numericOutputs[0] = numericOutputs[0] && destinationNumeric
		numericOutputs[1] = sourceNumeric && destinationNumeric
	} else {
		address := x86ResultIncomingPointerAddressIdentity(form.destination, state, arch)
		if !form.spec.pair {
			address = x86ResultNativeRMWAddress(ins, form.destination, state, owned, arch)
		}
		if !address {
			return false, true // No SB, FP/AUTO or numerical base is inferred.
		}
	}
	for index, reg := range outputs {
		root, mask, valid := x86ResultGP(reg, width, arch)
		if !valid {
			return false, true
		}
		// The accumulator write is conditional. In particular, a successful
		// dword CAS preserves its old high half; no unconditional zero extension.
		// A successful CAS may retain the opaque expected value. A register
		// destination may instead receive opaque desired bits. Only bytes
		// numerical on both outcomes remain NUM; neither outcome grants a
		// pointer identity for unknown native contents or selected values.
		if numericOutputs[index] {
			state.gp[root] |= mask
		} else {
			state.gp[root] &^= mask
		}
		state.pointerGP[root] = false
	}
	if form.spec.pair {
		state.flags |= x86ByteFlagZF // 8B/16B leave the other status flags unchanged.
	} else {
		state.flags = x86ByteFlagsAll
	}
	return true, true
}
