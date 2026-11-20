package plan9asm

import "fmt"

// Only the complete legacy MOVSS/MOVSD source grammar selects this loader.
// FP fields, constants and register copies retain their existing bit-view
// contracts. Native memory is an exact unaligned, mandatory m32/m64 read.
func (c *amd64Ctx) loadLegacyScalarMoveSource(ins Instr, bits int) (string, error) {
	form, known, err := amd64ScalarVectorMoveProperties(ins, c.goarch)
	if err != nil {
		return "", err
	}
	if !known || !form.spec.legacy || form.spec.bits != bits {
		return "", fmt.Errorf("%s does not have the required legacy scalar move source", ins.Op)
	}
	source := ins.Args[form.low]
	if form.memory != 0 || source.Kind != OpMem && source.Kind != OpSym {
		if bits == 32 {
			return c.evalF32(source)
		}
		return c.evalF64(source)
	}
	if ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride {
		return "", fmt.Errorf("%w: %s needs its original native address-size binding", ErrProbeNeedsContext, ins.Op)
	}
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(source)
	if err != nil {
		return "", err
	}
	loaded, scalar := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load volatile i%d, %s %s, align 1\n", loaded, bits, pointerType, pointer)
	fmt.Fprintf(c.b, "  %%%s = bitcast i%d %%%s to %s\n", scalar, bits, loaded, amd64FloatingScalarType(bits))
	return "%" + scalar, nil
}

// The public observer keeps logical-only storage. Only the paired legacy
// volatile emitter can continue an actual incoming-pointer m32/m64 access.
// Register copies preserve old high X bytes; memory copies zero those bytes.
// Both preserve every bit above 127, with no new storage or pointer facts.
func x86ResultLegacyScalarMoveStep(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string, native bool) (bool, bool) {
	form, recognized, err := amd64ScalarVectorMoveProperties(ins, arch)
	if !recognized || !form.spec.legacy {
		return false, false
	}
	if err != nil || form.mask >= 0 || len(ins.Args) != 2 {
		return false, true
	}
	width := int64(form.spec.bits / 8)
	mask := uint16(1)<<uint(width) - 1
	xreg := func(operand Operand) (int, bool) {
		index, valid := amd64ParseXReg(operand.Reg)
		return index, operand.Kind == OpReg && valid && index < 16 && (arch != "386" || index < 8)
	}
	first, last := ins.Args[0], ins.Args[1]
	if source, valid := xreg(first); valid {
		if state.xmm[source]&mask != mask {
			return false, true
		}
	} else if !form.literal && !x86ResultReadWithNativeContinuation(ins, first, width, state, owned, arch, native) {
		return false, true
	}
	if destination, valid := xreg(last); valid {
		known := state.xmm[destination] | mask
		if form.memory == 0 || form.legacyZero {
			known = 0xffff
		}
		state.writeVector(destination, 16, uint64(known), true)
		return true, true
	}
	if x86ResultScalarLaneNativeStore(ins, last, state, arch, native) {
		// The selected source bytes were checked above. The exact native
		// write defines no logical bytes or reusable memory/address fact.
		return true, true
	}
	return x86ResultStore(last, width, state, owned, resultOffset, arch), true
}
