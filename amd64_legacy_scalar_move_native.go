package plan9asm

import "fmt"

func (c *amd64Ctx) emitLegacyScalarMove(ins Instr, form amd64ScalarVectorMoveForm) error {
	value, err := c.loadLegacyScalarMoveSource(ins, form)
	if err != nil {
		return err
	}
	destination := ins.Args[form.destination]
	bits := form.spec.bits
	switch destination.Kind {
	case OpReg:
		return c.storeLegacyScalarMoveRegister(destination.Reg, value, bits, form.preservesLegacyUpperX())
	case OpFP:
		return c.storeScalarFPFloat(destination.FPOffset, bits, value)
	case OpMem:
		addr, err := c.addrFromMem(destination.Mem)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store volatile %s %s, ptr %s, align 1\n",
			amd64FloatingScalarType(bits), value, c.ptrFromAddrI64(addr))
	case OpSym:
		ptr, err := c.ptrFromSB(destination.Sym)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store %s %s, ptr %s, align 1\n", amd64FloatingScalarType(bits), value, ptr)
	default:
		return fmt.Errorf("invalid legacy scalar move destination %s", destination.String())
	}
	return nil
}

// FP fields, constants and register copies retain their bit-view contracts.
// Native memory is an exact unaligned, mandatory m32/m64 read.
func (c *amd64Ctx) loadLegacyScalarMoveSource(ins Instr, form amd64ScalarVectorMoveForm) (string, error) {
	bits := form.spec.bits
	source := ins.Args[form.low]
	if form.memory != form.low || source.Kind == OpFP {
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
	if err != nil {
		return false, true
	}
	width := int64(form.spec.bits / 8)
	mask := uint16(1)<<uint(width) - 1
	first, last := ins.Args[form.low], ins.Args[form.destination]
	if !form.literal {
		if form.memory == form.low {
			if !x86ResultReadWithNativeContinuation(ins, first, width, state, owned, arch, native) {
				return false, true
			}
		} else {
			source, _ := amd64ParseXReg(first.Reg)
			if state.xmm[source]&mask != mask {
				return false, true
			}
		}
	}
	if !form.memoryWrite {
		destination, _ := amd64ParseXReg(last.Reg)
		known := uint16(0xffff)
		if form.preservesLegacyUpperX() {
			known = state.xmm[destination] | mask
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
