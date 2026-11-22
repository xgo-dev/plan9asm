package plan9asm

import "math"

func fixedLocalRegisterBitStringStep(ins *Instr, state *x86FixedLocalState, proof *x86FixedLocalProof,
	residue int, index, destination x86TypedByteOperand) error {
	if !fixedLocalNumericRead(index.operand, index.width, state) {
		return goAMD64FrameContext("fixed local bit string requires a numerical register index")
	}
	address, err := fixedLocalMemoryAddress(*ins, destination.index, proof.frame)
	if err != nil {
		return err
	}
	if _, private := state.pointers[address.Base]; !private {
		// An incoming native address may fault as usual. A static/global
		// address needs an extent for the indexed word, beyond its base.
		if state.opaque[address.Base].readonly() {
			return goAMD64FrameContext("fixed local bit string has no indexed static extent")
		}
		_, _, err := fixedLocalMemoryAccess(ins, destination.index, state, proof, residue,
			destination.width, 1, destination.write, false)
		return err
	}

	base, resolved := fixedLocalPrivateOffset(address, state)
	first, last, bounded := fixedLocalBitStringOffsets(index, state)
	if !resolved || !bounded || first < 0 && base < math.MinInt64-first || first > 0 && base > math.MaxInt64-first {
		return goAMD64FrameContext("fixed local bit string requires a bounded private word index")
	}
	offset := base + first
	width := last - first + destination.width
	if err := fixedLocalRecordPrivateMemory(ins, destination.index, state, proof, residue,
		offset, width, 1, destination.write, true); err != nil {
		return err
	}
	if err := fixedLocalMachineBytesRead(state, proof, offset, width); err != nil {
		return err
	}
	if destination.write {
		// Every possible word was already defined. Revoke higher-level
		// facts for every byte that the read-modify-write can change.
		return fixedLocalMachineBytesStore(state, proof, offset, width)
	}
	return nil
}

func fixedLocalBitStringOffsets(index x86TypedByteOperand, state *x86FixedLocalState) (int64, int64, bool) {
	bounds, bounded := state.ranges[index.operand.Reg]
	if value, known := state.constants[index.operand.Reg]; known {
		bounds, bounded = x86UnsignedRange{uint64(value), uint64(value)}, true
	}
	bits := int(index.width * 8)
	if !bounded || bounds.minimum>>bits != bounds.maximum>>bits {
		return 0, 0, false
	}
	// Truncate to the encoded operand width, then interpret it as signed.
	// A range straddling the sign bit is not one contiguous signed interval.
	shift := 64 - bits
	first := int64(bounds.minimum<<shift) >> shift
	last := int64(bounds.maximum<<shift) >> shift
	if first > last {
		return 0, 0, false
	}
	wordShift := bitTestLog2(bits)
	return (first >> wordShift) * index.width, (last >> wordShift) * index.width, true
}
