package plan9asm

import "fmt"

func (c *amd64Ctx) lowerScalarExtensionMove(op Op, ins Instr) error {
	form, recognized, err := x86ScalarExtensionProperties(op, ins, c.goarch)
	if err != nil {
		return err
	}
	if !recognized {
		return fmt.Errorf("unrecognized scalar extension opcode %s: %q", op, ins.Raw)
	}
	spec := form.spec
	sourceType := amd64IntegerTypeForBits(spec.sourceBits)
	destinationType := amd64IntegerTypeForBits(spec.destinationBits)
	var value string
	native := x86OrdinaryNativeMemoryOperand(form.source, c.goarch) ||
		x86CallerMemoryCertified(ins, 0) || c.fixedLocalMemoryCertified(ins, 0)
	if native {
		if ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride {
			return fmt.Errorf("%w: scalar extension needs its original native address size", ErrProbeNeedsContext)
		}
		pointer, pointerType, _, pointerErr := c.packedVectorMemoryPointer(form.source)
		if pointerErr != nil {
			return pointerErr
		}
		loaded := c.newTmp()
		// Even a dead extension must read (and possibly fault on) its exact
		// source width. No validity or alignment assumption follows.
		fmt.Fprintf(c.b, "  %%%s = load volatile %s, %s %s, align 1\n", loaded, sourceType, pointerType, pointer)
		value = "%" + loaded
	} else {
		value, err = c.evalIntSized(form.source, sourceType)
	}
	if err != nil {
		return err
	}
	if spec.sourceBits < spec.destinationBits {
		extended := c.newTmp()
		extension := "zext"
		if spec.signed {
			extension = "sext"
		}
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", extended, extension, sourceType, value, destinationType)
		value = "%" + extended
	}
	return c.storeRegSized(form.result, destinationType, value)
}

// Only the paired volatile emitter can supply these conditional numerical
// result bytes. This creates no reusable pointee, bounds or caller proof.
func x86LoweredScalarExtensionRead(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	form, known, err := x86ScalarExtensionProperties(ins.Op, ins, arch)
	if !known || err != nil || form.source.Kind != OpMem || form.source.Mem.Sym != "" ||
		!x86OrdinaryNativeMemoryOperand(form.source, arch) || ins.x86NumericalRead != nil {
		return false, false
	}
	if ins.x86Encoded || ins.x86SourceRaw != nil || ins.x86RawNearReturn != nil ||
		ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 ||
		!x86ResultReadWithNativeGPContinuation(ins, form.source, int64(form.spec.sourceBits/8), state, owned, arch) {
		return false, true
	}
	return x86ResultStore(Operand{Kind: OpReg, Reg: form.result}, int64(form.spec.destinationBits/8),
		state, owned, resultOffset, arch), true
}
