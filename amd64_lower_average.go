package plan9asm

import "fmt"

func (c *amd64Ctx) lowerPackedUnsignedAverage(op Op, ins Instr) (bool, bool, error) {
	return c.lowerPackedPhysical(op, ins, x86PackedAverage)
}

func (c *amd64Ctx) lowerPackedAverageForm(op Op, ins Instr, form x86PackedPhysicalForm) (bool, bool, error) {
	ins.Op = op
	if err := x86LegacyMMXReadEmitterContext(ins, c.goarch); err != nil {
		return true, false, err
	}
	first, second, destination := form.source, ins.Args[form.second], ins.Args[form.destination]
	if form.legacy && !form.mmx && form.memory >= 0 {
		// A virtual FP/SP/BP view is not the source's native aligned m128.
		// Only the existing exact fixed-local certificate supplies that backing.
		virtual := first.Kind == OpFP
		if first.Kind == OpMem {
			virtual = !x86OrdinaryNativeMemoryOperand(first, c.goarch) && !c.fixedLocalMemoryCertified(ins, form.memory)
		}
		if virtual {
			return true, false, fmt.Errorf("%w: legacy packed average m128 needs original native storage, not virtual FP/SP/BP alignment", ErrProbeNeedsContext)
		}
	}
	if form.memory >= 0 && first.Kind == OpFP {
		if err := c.validateX86PackedShiftFPSpan(first.FPOffset, form.memoryBytes); err != nil {
			return true, false, err
		}
	}
	bits := form.spec.outputBits
	lanes := form.byteWidth * 8 / bits
	if form.mmx {
		var a string
		var err error
		if first.Kind == OpReg {
			a, err = c.loadReg(first.Reg)
		} else {
			// Exact m64 bytes, including independent logical FP fields. Native
			// reads stay observable without inventing an x87/tag-state bridge.
			a, err = c.loadPackedUnpackMMXSource(first, 8)
		}
		if err != nil {
			return true, false, err
		}
		b, err := c.loadReg(second.Reg)
		if err != nil {
			return true, false, err
		}
		value := c.emitPackedUnsignedAverage(lanes, bits, c.bitcastI64ToIntegerLanes(lanes, bits, a), c.bitcastI64ToIntegerLanes(lanes, bits, b))
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to i64\n", out, lanes, bits, value)
		return true, false, c.storeReg(destination.Reg, "%"+out)
	}
	mnemonic := "pavgb"
	if bits == 16 {
		mnemonic = "pavgw"
	}
	return true, false, c.emitPackedBinaryE4(ins, form.x86PackedBinaryForm, form.spec.memoryBits,
		mnemonic, c.emitPackedUnsignedAverage)
}

func (c *amd64Ctx) emitPackedUnsignedAverage(lanes, laneBits int, first, second string) string {
	narrowType := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
	wideBits := laneBits * 2
	wideType := fmt.Sprintf("<%d x i%d>", lanes, wideBits)
	firstWide := c.newTmp()
	secondWide := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", firstWide, narrowType, first, wideType)
	fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", secondWide, narrowType, second, wideType)
	sum := c.newTmp()
	rounded := c.newTmp()
	average := c.newTmp()
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", sum, wideType, firstWide, secondWide)
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %s\n", rounded, wideType, sum, llvmSplatSignedInteger(lanes, wideBits, 1))
	fmt.Fprintf(c.b, "  %%%s = lshr %s %%%s, %s\n", average, wideType, rounded, llvmSplatSignedInteger(lanes, wideBits, 1))
	fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", result, wideType, average, narrowType)
	return "%" + result
}
