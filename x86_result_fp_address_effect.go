package plan9asm

// This is only the validated named FP-address write shape. The private
// observer separately needs mapped typed storage; the post-consumer uses the
// same shape only to revoke the exact destination's old identities.
func x86LogicalFPLEAWriteShape(ins Instr, arch string) (int, uint8, int64, bool) {
	if len(ins.Args) == 2 && ins.Args[0].Kind == OpFPAddr {
		view, known, err := x86NamedFrameMoveAddressInstruction(ins, arch)
		if !known || err != nil {
			return 0, 0, 0, false
		}
		ins = view
	}
	if !x86ResultNamedPredicateInstruction(ins) || len(ins.Args) != 2 ||
		ins.Args[0].Kind != OpFP || ins.Args[0].Mem != (MemRef{}) {
		return 0, 0, 0, false
	}
	width, err := x86LEAOperandWidth(ins, arch)
	if err != nil || arch != "amd64" && arch != "386" {
		return 0, 0, 0, false
	}
	index, mask, valid := x86ResultGP(ins.Args[1].Reg, width, arch)
	return index, mask, width, valid && (arch != "amd64" || index != 14)
}

// Taking an address reads no data from that slot. This private fallback
// retains only unknown address bytes, not numerical values, a reusable alias
// or native backing. Full-word result/readonly-I1 producers run first.
func x86ResultUnusedFPAddressStep(ins Instr, state *x86ResultState, owned []bool,
	resultOffset int64, arch string) (bool, bool) {
	index, mask, width, known := x86LogicalFPLEAWriteShape(ins, arch)
	if !known {
		return false, false
	}
	offset := ins.Args[0].FPOffset
	if state == nil || offset < 0 || offset >= int64(len(owned)) || !owned[offset] || offset >= int64(len(state.fp)) {
		return false, true
	}
	if offset >= resultOffset {
		matches := 0
		for _, slot := range state.resultAddressSlots {
			if slot.valid && slot.start >= resultOffset && slot.end > slot.start &&
				slot.end <= int64(len(owned)) && offset >= slot.start && offset < slot.end {
				for position := slot.start; position < slot.end; position++ {
					if !owned[position] {
						return false, true
					}
				}
				matches++
			}
		}
		if matches != 1 {
			return false, true // No ordinary result-storage producer or unique field.
		}
	} else {
		if !state.fp[offset] {
			return false, true // Unmapped/pointer parameter bytes are not numerical storage.
		}
		for start := range state.pointerFP {
			if offset >= start && offset < start+x86ResultPointerWord(arch) {
				return false, true
			}
		}
	}
	state.gp[index] &^= mask
	state.canonicalGP[index] &^= mask
	if width == 4 {
		state.gp[index] |= 0xf0 // Architectural upper32 zero, not initialized address bits.
		state.canonicalGP[index] |= 0xf0
	}
	state.pointerGP[index], state.callerAddressGP[index] = false, false
	state.callerAddressOrigin[index] = 0
	state.resultAddressGP[index] = x86ResultSlotAddress{}
	state.predicate = x86ResultPredicate{}
	return true, true
}
