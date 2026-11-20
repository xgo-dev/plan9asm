package plan9asm

// Outgoing ABI0 bytes are distinct from FP and negative named AUTO. They are
// observed only at declared one-byte parameter/result offsets of a proved
// same-file readonly leaf, never from FrameSize alone.
func x86ABI0BoolCallStep(ordinal int, ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	plan := state.boolCalls
	if plan == nil {
		return false, false
	}
	if ins.Op == "CALL" {
		sig, known := plan.calls[ordinal]
		if !known || arch != plan.source.options.Goarch || len(ins.Args) != 1 || ins.Args[0].Kind != OpSym {
			return false, true
		}
		if sig.Ret != Void && !state.shapeOnly && (!state.boolOutgoing[0] || !state.boolOutgoingCanonical[0]) {
			return false, true
		}
		// No caller GP, SIMD, mask, pointer, slot-address or FLAGS state is
		// preserved by the original CALL, even if logical SSA happens to leave
		// a register alloca untouched. Void supplies no result byte at all.
		state.gp = [16]uint8{}
		state.canonicalGP = [16]uint8{}
		state.xmm = [32]uint16{}
		state.vectorUpper = [32]uint64{}
		state.masks = [8]bool{}
		state.pointerGP = [16]bool{}
		state.callerAddressGP = [16]bool{}
		state.callerAddressOrigin = [16]uint16{}
		state.bitScanPending = x86ResultBitScanPending{}
		state.predicate = x86ResultPredicate{}
		state.resultAddressGP = [16]x86ResultSlotAddress{}
		if state.boolFrameGP != nil {
			state.boolFrameGP = new([16]x86ResultSlotAddress)
		}
		state.flags = 0
		state.direction = x86ResultDirectionUnknown
		if state.x87 != nil {
			state.x87.revoke()
		}
		if sig.Ret == Void {
			return true, true // No numerical/canonical FP or outgoing byte is new.
		}
		offset := int(sig.Frame.Results[0].Offset)
		state.boolOutgoing[offset], state.boolOutgoingCanonical[offset] = true, true
		return true, true
	}
	sp := false
	for _, arg := range ins.Args {
		sp = sp || arg.Kind == OpMem && arg.Mem.Base == SP
	}
	if !sp {
		return false, false
	}
	if ins.Op != "MOVB" || len(ins.Args) != 2 || isX86RawDirective(ins) {
		return false, true
	}
	first, last := ins.Args[0], ins.Args[1]
	for index, arg := range ins.Args {
		if arg.Kind == OpMem && arg.Mem.Base == SP {
			if _, valid := x86ABI0BoolOutgoingOffset(arg, plan); !valid {
				return false, true
			}
			width, write, known := x86InstructionMemoryShape(ins, index, arch)
			if !known || width != 1 || write != (index == 1) {
				return false, true
			}
		}
	}
	if offset, valid := x86ABI0BoolOutgoingOffset(last, plan); valid {
		if first.Kind != OpReg && first.Kind != OpImm {
			return false, true
		}
		if !x86ResultRead(first, 1, state, owned, arch) {
			return false, true
		}
		canonical := false
		if first.Kind == OpImm {
			canonical = first.ImmRaw == "" && !first.ImmIsFloat && (first.Imm == 0 || first.Imm == 1)
		} else {
			root, mask, valid := x86ResultGP(first.Reg, 1, arch)
			canonical = valid && state.canonicalGP[root]&mask == mask
		}
		state.boolOutgoing[offset], state.boolOutgoingCanonical[offset] = true, canonical
		return true, true
	}
	if offset, valid := x86ABI0BoolOutgoingOffset(first, plan); valid {
		if last.Kind != OpReg || !state.boolOutgoing[offset] || !x86ResultStore(last, 1, state, owned, resultOffset, arch) {
			return false, true
		}
		root, mask, valid := x86ResultGP(last.Reg, 1, arch)
		if !valid {
			return false, true
		}
		if state.boolFrameGP != nil {
			state.boolFrameGP[root] = x86ResultSlotAddress{}
		}
		state.canonicalGP[root] &^= mask
		if state.boolOutgoingCanonical[offset] {
			state.canonicalGP[root] |= mask
		}
		return true, true
	}
	return false, true
}
