package plan9asm

func x86RawScalarObserverSource(ins Instr, arch string) bool {
	_, count, err := x86ScalarBitCountProperties(ins.Op, ins, arch)
	if !count {
		form, mask, maskErr := x86MoveMaskProperties(ins.Op, ins, arch)
		if !mask || maskErr != nil || form.byteWidth == 8 {
			return false // Physical MMX/x87 state retains its separate owner.
		}
	}
	return err == nil && x86RawOrdinaryVectorSource(ins, arch)
}

// Exact decoded source identity composes with the existing scalar-count or
// move-mask effect. Only the paired native read may supply numerical bytes;
// declaration, caller, physical entry and reusable-memory roles stay strict.
func x86LoweredRawScalarObserverStep(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	_, count, _ := x86ScalarBitCountProperties(ins.Op, ins, arch)
	if !count {
		if _, mask, _ := x86MoveMaskProperties(ins.Op, ins, arch); !mask {
			return false, false
		}
	}
	if x86ResultNamedPredicateInstruction(ins) {
		return false, false
	}
	if !x86RawScalarObserverSource(ins, arch) {
		return false, true
	}
	local := ins
	local.x86Encoded, local.x86SourceRaw = false, nil
	if count {
		if accepted, known := x86LoweredScalarBitCountNativeRead(local, state, owned, resultOffset, arch); known {
			return accepted, true
		}
	}
	return x86ResultTransfer(local, state, owned, resultOffset, arch), true
}
