package plan9asm

// A pending scan result is tied to its immediately following ZF branch.
// It is not a known value, nonzero-input claim, pointer or memory permission.
// The zero edge retains exactly its prior numerical byte knowledge; only the
// nonzero edge independently defines the written destination. Older dword
// zero-input opcodes may clear the upper half instead of preserving it: a
// previously known byte stays known in either case, but an unknown one does
// not become known without that nonzero edge. No CPU generation is guessed.
type x86ResultBitScanPending struct {
	register uint8
	mask     uint8 // Zero means there is no pending definition.
}

func x86ResultBitScanStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	return x86ResultBitScanStepWithRead(ins, state, owned, arch, false)
}

// Only the paired exact-width volatile emitter may supply numerical source
// bytes after its read. Standalone queries, source permissions and the
// zero-input prior destination retain their independent requirements.
func x86ResultBitScanStepWithRead(ins Instr, state *x86ResultState, owned []bool, arch string, native bool) (bool, bool) {
	spec, known, err := x86ScalarBitScanProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if ins.x86Encoded || ins.x86SourceRaw != nil || ins.x86RawNearReturn != nil ||
		ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 {
		return false, true // Named effects never inherit a raw/native source role.
	}
	width := int64(spec.bits / 8)
	index, mask, valid := x86ResultGP(ins.Args[1].Reg, width, arch)
	if !valid || !x86ResultReadWithNativeContinuation(ins, ins.Args[0], width, state, owned, arch, native) {
		return false, true
	}
	if width == 4 && arch == "amd64" {
		mask = 0xff // The valid dword result also clears the upper dword.
	}
	// Every affected byte is either its prior numerical value on zero input
	// (or known zero for the historical dword upper-half behavior) or a defined
	// scan result on nonzero input. Preserve knowledge, never invent a value.
	state.canonicalGP[index] &^= mask
	state.pointerGP[index], state.callerAddressGP[index] = false, false
	state.resultAddressGP[index] = x86ResultSlotAddress{}
	state.flags = x86ByteFlagZF // Other flags have no portable cross-CPU definition.
	state.bitScanPending = x86ResultBitScanPending{register: uint8(index), mask: mask}
	nonzero := false
	if ins.Args[0].Kind == OpReg && state.predicate.kind == x86ResultNonzeroMaskGP && int(state.predicate.width) <= spec.bits {
		source, _, valid := x86ResultGP(ins.Args[0].Reg, width, arch)
		nonzero = valid && uint8(source) == state.predicate.register
	}
	if state.shapeOnly || nonzero {
		state.gp[index] |= mask // Shape validation is never a reaching-state proof.
	}
	if nonzero {
		state.bitScanPending = x86ResultBitScanPending{}
	}
	return true, true
}

func x86ResultBitScanEdge(state x86ResultState, ins Instr, edge int) x86ResultState {
	if !isAMD64ConditionalBranch(ins.Op) {
		return state
	}
	pending := state.bitScanPending
	state.bitScanPending = x86ResultBitScanPending{}
	if pending.mask == 0 {
		return state
	}
	nonzero := false
	switch ins.Op {
	case "JE", "JEQ", "JZ":
		nonzero = edge == 0 // CFG edges retain fallthrough before taken.
	case "JNE", "JNZ":
		nonzero = edge == 1
	}
	if nonzero {
		state.gp[pending.register] |= pending.mask
	}
	return state
}
