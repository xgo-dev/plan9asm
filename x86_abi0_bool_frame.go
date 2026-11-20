package plan9asm

import "strings"

// A declared ABI0 bool must retain its physical byte until canonical RET.
// AMD64 signatures without declared result slots keep their independent
// register-return convention; this query grants no frame or entry permission.
func x86ABI0BoolResultNeedsProof(sig FuncSig, arch string) bool {
	return sig.Ret == I1 && (arch == "386" || arch == "amd64" && len(sig.Frame.Results) != 0)
}

// This lowering-only logical role extends declared bool-byte transport, not
// SDK literal/native entry, caller backing or the direct-tail result domain.
// Actual signature/source producers retain their independent authentication.
func x86ABI0LogicalBoolFrameRole(fn Func, sig FuncSig, arch string) bool {
	if x86CustomHelperBoolFrameRole(fn, sig, arch) {
		return true // Actual root layout and a complete source/result-pointer plan.
	}
	if !x86ABI0BoolDeclarationRole(sig, arch) || strings.Contains(fn.Sym, "<") ||
		fn.FrameSize != 0 && (fn.x86BoolCalls == nil || !fn.x86BoolCalls.matches(fn, sig, arch)) ||
		len(fn.X86RawText) != 0 || fn.x86SourceStack != nil || fn.x86FixedLocal != nil || fn.x86DirectTailRoot != nil {
		return false
	}
	if fn.ArgSize != sig.Frame.Results[0].Offset+1 {
		return false
	}
	for _, ins := range fn.Instrs {
		if ins.x86Encoded || ins.x86SourceRaw != nil || ins.x86RawNearReturn != nil || ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride {
			return false
		}
	}
	return true
}

// This bounded typed-layout query grants no source, terminal or FP permission.
// Native/borrowed target roles are not independent logical bool declarations.
func x86ABI0BoolDeclarationRole(sig FuncSig, arch string) bool {
	if arch != "386" && arch != "amd64" || sig.Ret != I1 || len(sig.ArgRegs) != 0 || len(sig.Frame.Results) != 1 || sig.ARMEntry != nil ||
		sig.ARM64GoRegisterABI != nil || sig.ARM64ClosureABI != nil || sig.WASMContext != "" || sig.WASMNative || sig.x86BorrowedBoolTail {
		return false
	}
	result := sig.Frame.Results[0]
	if result.Type != I1 || result.Index != 0 || result.Field != -1 || len(result.Fields) != 0 ||
		result.Offset < 0 || result.Offset >= 4096 || len(sig.Frame.Params) > 4096 || len(sig.Args) > 4096 {
		return false
	}
	represented := make(map[int]bool)
	roles := make(map[string]bool)
	occupied := make([]bool, result.Offset)
	for _, slot := range sig.Frame.Params {
		width := x86FrameScalarBytes(slot.Type, arch)
		if width <= 0 || slot.Offset < 0 || slot.Offset > result.Offset-width {
			return false
		}
		role, valid := x86ResultParameterRole(sig.Args, slot)
		if !valid || roles[role] {
			return false
		}
		roles[role] = true
		represented[slot.Index] = true
		for offset := slot.Offset; offset < slot.Offset+width; offset++ {
			if occupied[offset] {
				return false
			}
			occupied[offset] = true
		}
	}
	return len(represented) == len(sig.Args)
}

func x86ABI0BoolFrameAliasNeeded(fn Func, arch string) bool {
	lea := Op("LEAQ")
	if arch == "386" {
		lea = "LEAL"
	}
	for _, ins := range fn.Instrs {
		if ins.Op == lea && len(ins.Args) == 2 && ins.Args[0].Kind == OpFP {
			return true
		}
	}
	return false
}

func x86ABI0BoolFrameSlot(state *x86ResultState, offset, width int64, arch string) (FrameSlot, bool) {
	for _, slot := range state.boolFrameSlots {
		size := x86FrameScalarBytes(slot.Type, arch)
		if width > 0 && offset >= slot.Offset && offset <= slot.Offset+size-width {
			return slot, true
		}
	}
	return FrameSlot{}, false
}

// Input stores alter the existing private logical parameter copy, not caller
// memory. A physical bool byte can hold a numeric intermediate until RET; it
// must not be normalized to I1 merely by a read or write of the shadow slot.
func x86ABI0BoolFrameNUMTransfer(ordinal int, ins Instr, state *x86ResultState, owned []bool, resultOffset int64,
	arch string, transfer x86ResultSourceTransfer) bool {
	if state.boolReadonlyInputs {
		for index, arg := range ins.Args {
			if arg.Kind == OpFP && arg.FPOffset < resultOffset {
				_, write, known := x86InstructionMemoryShape(ins, index, arch)
				if !known || write {
					return false
				}
			}
		}
	}
	if form, known, err := x86ConditionalSetProperties(ins.Op, ins, arch); known && err == nil &&
		form.destination.Kind == OpFP && form.destination.FPOffset < resultOffset {
		if slot, valid := x86ABI0BoolFrameSlot(state, form.destination.FPOffset, 1, arch); valid && slot.Type == I1 {
			required := x86ByteConditionFlags(form.condition)
			if required != 0 && state.flags&required == required {
				state.fp[form.destination.FPOffset] = true
				return true
			}
		}
	}
	if len(ins.Args) == 2 && ins.Args[1].Kind == OpFP && ins.Args[1].FPOffset < resultOffset {
		width := x86RawReturnScalarMoveBytes(ins.Op)
		if slot, valid := x86ABI0BoolFrameSlot(state, ins.Args[1].FPOffset, width, arch); valid && slot.Type == I1 && width == 1 &&
			(ins.Args[0].Kind == OpImm || ins.Args[0].Kind == OpReg) && x86ResultRead(ins.Args[0], width, state, owned, arch) {
			state.fp[ins.Args[1].FPOffset] = true
			return true
		}
	}
	return transfer(ordinal, ins, state, owned, resultOffset, arch)
}

func x86ABI0BoolFrameTransfer(ordinal int, original Instr, state *x86ResultState, owned []bool, resultOffset int64,
	arch string, transfer x86ResultSourceTransfer) bool {
	ins := x86SourceMoveInstruction(original, arch)
	if accepted, known := x86ABI0BoolCallStep(ordinal, ins, state, owned, resultOffset, arch); known {
		return accepted
	}
	aliases := state.boolFrameGP
	word := x86ResultPointerWord(arch)
	lea, move := Op("LEAQ"), Op("MOVQ")
	if arch == "386" {
		lea, move = "LEAL", "MOVL"
	}
	alias := func(arg Operand) x86ResultSlotAddress {
		if aliases != nil && arg.Kind == OpReg {
			if root, _, valid := x86ResultGP(arg.Reg, word, arch); valid {
				return aliases[root]
			}
		}
		return x86ResultSlotAddress{}
	}
	writeAlias := func(destination Operand, value x86ResultSlotAddress) bool {
		root, _, valid := x86ResultGP(destination.Reg, word, arch)
		if aliases == nil || destination.Kind != OpReg || !valid || root == 4 || root == 5 || !value.valid {
			return false
		}
		aliases[root] = value
		state.gp[root], state.canonicalGP[root] = 0, 0
		state.pointerGP[root], state.callerAddressGP[root] = false, false
		return true
	}
	if len(ins.Args) == 2 {
		first, last := ins.Args[0], ins.Args[1]
		if ins.Op == lea && first.Kind == OpFP {
			if width, err := x86LEAOperandWidth(ins, arch); err != nil || width != word {
				return false
			}
			slot, valid := x86ABI0BoolFrameSlot(state, first.FPOffset, 1, arch)
			return valid && writeAlias(last, x86ResultSlotAddress{start: slot.Offset, end: slot.Offset + x86FrameScalarBytes(slot.Type, arch), offset: first.FPOffset, valid: true})
		}
		if ins.Op == move {
			if value := alias(first); value.valid {
				return writeAlias(last, value)
			}
		}
		if ins.Op == lea && first.Kind == OpMem {
			if value := alias(Operand{Kind: OpReg, Reg: first.Mem.Base}); value.valid {
				if width, err := x86LEAOperandWidth(ins, arch); err != nil || width != word || !x86ResultSlotMemory(first.Mem) ||
					first.Mem.Off < value.start-value.offset || first.Mem.Off >= value.end-value.offset {
					return false
				}
				value.offset += first.Mem.Off
				return writeAlias(last, value)
			}
		}
	}
	local := original
	local.Args = append([]Operand(nil), original.Args...)
	projected := false
	for index, arg := range ins.Args {
		if arg.Kind == OpMem {
			value := alias(Operand{Kind: OpReg, Reg: arg.Mem.Base})
			if alias(Operand{Kind: OpReg, Reg: arg.Mem.Index}).valid {
				return false
			}
			if !value.valid && !state.shapeOnly {
				continue
			}
			width, write, known := x86InstructionMemoryShape(ins, index, arch)
			move := x86RawReturnScalarMoveBytes(ins.Op) != 0
			_, extension, extensionErr := x86ScalarExtensionProperties(ins.Op, ins, arch)
			_, conditional, conditionalErr := x86ConditionalSetProperties(ins.Op, ins, arch)
			if aliases == nil || !known || width <= 0 || width > word || !x86ResultSlotMemory(arg.Mem) ||
				!(move || extension && extensionErr == nil || conditional && conditionalErr == nil) {
				if value.valid {
					return false
				}
				continue
			}
			if !conditional {
				if len(ins.Args) != 2 {
					return false
				}
				other := ins.Args[1-index]
				if other.Kind != OpReg && !(index == 1 && other.Kind == OpImm) {
					return false // A projection never invents a memory-to-memory row.
				}
			}
			if state.shapeOnly && !value.valid {
				for _, slot := range state.boolFrameSlots {
					if state.boolReadonlyInputs && write && slot.Offset < resultOffset {
						continue
					}
					if write && slot.Offset < resultOffset && slot.Type != I1 {
						continue // A numerical input cannot represent a writable bool/result byte.
					}
					if size := x86FrameScalarBytes(slot.Type, arch); size >= width {
						value = x86ResultSlotAddress{start: slot.Offset, end: slot.Offset + size, offset: slot.Offset, valid: true}
						break
					}
				}
			} else if arg.Mem.Off >= value.start-value.offset && arg.Mem.Off <= value.end-value.offset-width {
				value.offset += arg.Mem.Off
			} else {
				return false
			}
			if !value.valid {
				return false
			}
			local.Args[index] = Operand{Kind: OpFP, FPOffset: value.offset}
			projected = true
		}
		if alias(arg).valid && !x86ResultSlotOverwrite(ins, index, arch) {
			return false // No numerical observation, address return or escape.
		}
	}
	beforeFP, beforeGP := append([]bool(nil), state.canonicalFP...), state.canonicalGP
	var unprojected x86ResultState
	if state.shapeOnly && projected {
		unprojected = state.clone()
	}
	if !x86ABI0BoolFrameNUMTransfer(ordinal, local, state, owned, resultOffset, arch, transfer) {
		// A shape-only unknown base can be a logical alias or an incoming
		// pointer. If no logical slot represents its width, validate the
		// original instruction through the supplied transfer instead. This
		// disposable state never reaches a CFG edge; an actual alias still
		// requires its exact FP projection and cannot take this alternative.
		if unprojected.shapeOnly && transfer(ordinal, original, &unprojected, owned, resultOffset, arch) {
			*state = unprojected
			return true
		}
		return false
	}
	state.canonicalFP, state.canonicalGP = x86ABI0CanonicalBytesAfter(local, beforeFP, beforeGP, arch)
	// The paired lowering transfer may publish a cloned NUM state. Revoke the
	// aliases in that actual successor, never the pre-transfer array pointer.
	aliases = state.boolFrameGP
	if aliases != nil {
		var live [16]bool
		for root, value := range aliases {
			live[root] = value.valid
		}
		live = x86ResultCallerAddressesAfter(ins, live, nil, arch)
		for root := range aliases {
			if !live[root] {
				aliases[root] = x86ResultSlotAddress{}
			}
		}
	}
	return true
}
