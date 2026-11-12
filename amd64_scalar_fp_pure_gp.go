package plan9asm

// x86LoweredPureGPUnknownTransfer is a lowering-only availability fallback for
// a closed set of nontrapping, register/immediate GP operations. Unavailable
// scratch inputs are not initialized: their dependent outputs stay unknown.
// A later result, address, store or control use must pass the ordinary check.
//
// The caller first tries ordinary transfer on a separate state clone and uses
// this function only after failure. No partially mutated failed state may be
// supplied. The public/declaration-only checker deliberately has no fallback.
func x86LoweredPureGPUnknownTransfer(ins Instr, state *x86ResultState, arch string) bool {
	if ins.x86Encoded || ins.x86SourceRaw != nil || ins.x86RawNearReturn != nil ||
		ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 {
		return false
	}
	for _, operand := range ins.Args {
		if operand.Kind != OpReg && operand.Kind != OpImm ||
			operand.Kind == OpImm && (operand.ImmRaw != "" || operand.ImmIsFloat) {
			return false
		}
	}
	if form, known, err := x86ScalarCompareProperties(ins.Op, ins, arch); known {
		if err != nil || !form.test || form.memory >= 0 {
			return false
		}
		unknown := false
		for _, operand := range form.args {
			if operand.Kind == OpImm {
				continue
			}
			index, mask, valid := x86ResultGP(operand.Reg, int64(form.bits/8), arch)
			if operand.Kind != OpReg || !valid || state.pointerGP[index] {
				return false
			}
			unknown = unknown || state.gp[index]&mask != mask
		}
		if !unknown {
			return false // Preserve the ordinary fully numerical transfer.
		}
		// The paired TEST emitter always clears CF/OF, independently of
		// its scratch bits. ZF/SF/PF still depend on those bits, AF is
		// undefined, and no numerical register/pointer fact is produced.
		// Memory is excluded: its faulting read must never be skipped.
		state.flags = x86ByteFlagCF | x86ByteFlagOF
		return true
	}

	// Keep the nontrapping domain explicit. Future additions to the general
	// effect directory (e.g. division or a native effect) cannot opt in merely
	// by describing their byte inputs and outputs.
	shift, isShift, shiftErr := x86ScalarShiftProperties(ins.Op, ins, arch)
	extension, isExtension, extensionErr := x86ScalarExtensionProperties(ins.Op, ins, arch)
	rmw, isRMW, rmwErr := x86LockScalarRMWProperties(ins.Op, ins, arch)
	_, isIMUL, imulErr := x86ExplicitIMULProperties(ins.Op, ins, arch)
	_, isCMOV, cmovErr := x86ConditionalMoveProperties(ins.Op, ins, arch)
	if !isShift && !isExtension && !isRMW && !isIMUL && !isCMOV ||
		shiftErr != nil || extensionErr != nil || rmwErr != nil || imulErr != nil || cmovErr != nil {
		return false
	}
	effect, known, err := x86TypedGPByteEffect(ins.Op, ins, arch)
	if !known || err != nil || effect.dynamicMemory {
		return false
	}

	unknown := state.flags&effect.flagsRead != effect.flagsRead
	for _, operand := range effect.operands {
		if operand.operand.Kind == OpImm && !operand.write {
			continue
		}
		if operand.operand.Kind != OpReg {
			return false
		}
		index, mask, valid := x86ResultGP(operand.operand.Reg, operand.width, arch)
		if !valid || operand.read && state.pointerGP[index] {
			return false // An opaque incoming pointer is never a numerical input.
		}
		if operand.read && state.gp[index]&mask != mask {
			unknown = true
		}
	}
	if !unknown {
		return false // Do not turn some other strict failure into success.
	}

	before := state.gp
	for _, operand := range effect.operands {
		if !operand.write {
			continue
		}
		index, mask, _ := x86ResultGP(operand.operand.Reg, operand.width, arch)
		defined := uint8(0)
		if isExtension {
			defined = x86LoweredExtensionKnownBytes(extension, before, arch)
		} else if isShift && !shift.bmi2 && shift.count.Kind == OpImm && shift.maskedCount() == 0 {
			defined = before[index] & mask // Group2 count0 leaves its low bytes unchanged.
		} else if isRMW {
			defined = x86LoweredRMWKnownBytes(rmw.spec, effect, before, state.flags, arch)
			// The dependency directory uses low-relative bytes. The actual
			// typed operand still owns high-byte aliases such as AH/DH.
			for view := mask; view&1 == 0; view >>= 1 {
				defined <<= 1
			}
		}
		state.gp[index] = before[index]&^mask | defined
		if operand.width == 4 {
			state.gp[index] |= 0xf0 // Architectural dword write clears upper32.
		}
		state.pointerGP[index] = false
	}
	flagsWritten := effect.flagsDefined | effect.flagsKilled
	if isShift && !shift.bmi2 && shift.count.Kind == OpReg {
		// flagsDefined means unconditionally initialized, not every possible
		// write. In particular variable count0 can preserve old flags, while
		// a nonzero count computes new flags from the unknown data/count.
		flagsWritten = x86ByteFlagsAll
		switch shift.stem {
		case "RCL", "RCR", "ROL", "ROR":
			flagsWritten = x86ByteFlagCF | x86ByteFlagOF
		}
	}
	state.flags &^= flagsWritten
	return true
}

func x86LoweredRMWKnownBytes(spec x86LockScalarRMWSpec, effect x86TypedByteEffect, before [16]uint8,
	flags uint8, arch string) uint8 {
	inputs := uint8(0xff)
	for _, operand := range effect.operands {
		if !operand.read || operand.operand.Kind == OpImm {
			continue
		}
		root, mask, valid := x86ResultGP(operand.operand.Reg, operand.width, arch)
		if !valid {
			return 0
		}
		known := before[root] & mask
		for mask&1 == 0 {
			known >>= 1
			mask >>= 1
		}
		inputs &= known
	}
	var result uint8
	for output := 0; output < spec.bits/8; output++ {
		mask, carry := spec.numericalByteInputs(output)
		if mask != 0 && inputs&mask == mask && (!carry || flags&x86ByteFlagCF != 0) {
			result |= 1 << uint(output)
		}
	}
	return result
}

// Extensions copy individual source bytes. Zero fill is independent of every
// source bit; sign fill depends only on the source's most significant byte.
func x86LoweredExtensionKnownBytes(form x86ScalarExtensionForm, before [16]uint8, arch string) uint8 {
	sourceWidth := int64(form.spec.sourceBits / 8)
	index, mask, _ := x86ResultGP(form.source.Reg, sourceWidth, arch)
	input := before[index] & mask
	for mask&1 == 0 {
		mask >>= 1
		input >>= 1
	}
	known := input
	if !form.spec.signed || input&(1<<uint(sourceWidth-1)) != 0 {
		for b := sourceWidth; b < int64(form.spec.destinationBits/8); b++ {
			known |= 1 << uint(b)
		}
	}
	return known
}
