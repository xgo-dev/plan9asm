package plan9asm

import "fmt"

// lowerCompareExchange implements every operand row in Go 1.27's yrb_mb,
// yrl_ml, and yscond tables for the CMPXCHG family.
func (c *amd64Ctx) lowerCompareExchange(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, recognized, err := x86CompareExchangeProperties(op, ins, c.goarch)
	if !recognized {
		return false, false, nil
	}
	if err != nil {
		return true, false, err
	}
	if form.spec.pair {
		return c.lowerPairCompareExchange(string(op), form.spec.bits, ins)
	}
	return c.lowerScalarCompareExchange(string(op), form.spec.bits, ins)
}

func amd64CompareExchangeProperties(op string) (kind string, bits int, ok bool) {
	spec, recognized := x86CompareExchangeSpecs[Op(op)]
	if !recognized {
		return "", 0, false
	}
	kind = "scalar"
	if spec.pair {
		kind = "pair"
	}
	return kind, spec.bits, true
}

func (c *amd64Ctx) lowerScalarCompareExchange(baseOp string, bits int, ins Instr) (bool, bool, error) {
	form, recognized, err := x86CompareExchangeProperties(Op(baseOp), ins, c.goarch)
	if err != nil {
		return true, false, err
	}
	if !recognized || form.spec.pair || form.spec.bits != bits {
		return true, false, fmt.Errorf("%s %s has no matching scalar compare-exchange width", c.goarch, baseOp)
	}
	source, destination := form.source, form.destination
	if err := c.validateCompareExchangeFP(destination, bits); err != nil {
		return true, false, err
	}

	typ := amd64IntegerTypeForBits(bits)
	accumulator, err := c.loadReg(AX)
	if err != nil {
		return true, false, err
	}
	expected, err := c.evalIntSized(Operand{Kind: OpReg, Reg: AX}, typ)
	if err != nil {
		return true, false, err
	}
	desired, err := c.evalIntSized(source, typ)
	if err != nil {
		return true, false, err
	}

	var old, success string
	if destination.Kind == OpReg {
		old, err = c.evalIntSized(destination, typ)
		if err != nil {
			return true, false, err
		}
		equal := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, %s\n", equal, typ, expected, old)
		success = "%" + equal
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, %s %s, %s %s\n", selected, success, typ, desired, typ, old)
		if err := c.storeRegSized(destination.Reg, typ, "%"+selected); err != nil {
			return true, false, err
		}
	} else {
		ptr, ptrType, err := c.compareExchangePointer(destination)
		if err != nil {
			return true, false, err
		}
		old, success = c.emitScalarCompareExchangeNative(bits, destination, ptr, ptrType, expected, desired)
	}

	// On failure the accumulator receives the destination. On success it is not
	// written at all. In particular, CMPXCHGL zero-extends EAX only on failure;
	// a successful compare must preserve the original high half of RAX.
	if destination.Kind != OpReg || !amd64CompareExchangeDestinationIsAccumulator(destination.Reg, bits) {
		if err := c.storeScalarCompareExchangeAccumulator(accumulator, expected, old, success, typ); err != nil {
			return true, false, err
		}
	}
	difference := c.newTmp()
	// CMPXCHG compares the accumulator with the destination, so its arithmetic
	// flags come from accumulator - destination (Intel's temporary result).
	fmt.Fprintf(c.b, "  %%%s = sub %s %s, %s\n", difference, typ, expected, old)
	c.setScalarAddSubFlags(typ, false, expected, old, "%"+difference)
	// Keep the equality result authoritative even for unusual aliasing forms.
	fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", success, c.flagsZSlot)
	return true, false, nil
}

func (c *amd64Ctx) storeScalarCompareExchangeAccumulator(accumulator, expected, failureValue, success string, typ LLVMType) error {
	if typ == I32 {
		failure64 := c.newTmp()
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", failure64, failureValue)
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, i64 %s, i64 %%%s\n", selected, success, accumulator, failure64)
		return c.storeReg(AX, "%"+selected)
	}
	selected := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, %s %s, %s %s\n", selected, success, typ, expected, typ, failureValue)
	return c.storeRegSized(AX, typ, "%"+selected)
}

func amd64CompareExchangeDestinationIsAccumulator(reg Reg, bits int) bool {
	if bits == 8 {
		return reg == AX || reg == AL
	}
	return reg == AX
}

func (c *amd64Ctx) lowerPairCompareExchange(baseOp string, bits int, ins Instr) (bool, bool, error) {
	form, recognized, err := x86CompareExchangeProperties(Op(baseOp), ins, c.goarch)
	if err != nil {
		return true, false, err
	}
	if !recognized || !form.spec.pair || form.spec.bits != bits {
		return true, false, fmt.Errorf("%s %s has no matching pair compare-exchange width", c.goarch, baseOp)
	}
	destination := form.destination
	if err := c.validateCompareExchangeFP(destination, bits); err != nil {
		return true, false, err
	}

	ax, err := c.loadReg(AX)
	if err != nil {
		return true, false, err
	}
	dx, err := c.loadReg(DX)
	if err != nil {
		return true, false, err
	}
	bx, err := c.loadReg(BX)
	if err != nil {
		return true, false, err
	}
	cx, err := c.loadReg(CX)
	if err != nil {
		return true, false, err
	}
	ptr, ptrType, err := c.compareExchangePointer(destination)
	if err != nil {
		return true, false, err
	}
	old, success := c.emitPairCompareExchangeNative(bits, destination, ptr, ptrType, ax, dx, bx, cx)

	oldLow, oldHigh := c.compareExchangeSplitPair(old, bits)
	if err := c.storeCompareExchangePairAccumulator(AX, ax, oldLow, success, bits); err != nil {
		return true, false, err
	}
	if err := c.storeCompareExchangePairAccumulator(DX, dx, oldHigh, success, bits); err != nil {
		return true, false, err
	}
	fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", success, c.flagsZSlot)
	return true, false, nil
}

func (c *amd64Ctx) validateCompareExchangeFP(destination Operand, bits int) error {
	if destination.Kind != OpFP {
		return nil
	}
	context := func(reason string) error {
		return fmt.Errorf("%w: %s CMPXCHG FP native write at +%d(FP): %s", ErrProbeNeedsContext, c.goarch, destination.FPOffset, reason)
	}
	if bits == 128 {
		return context("logical FP storage has no original CMPXCHG16B native address/alignment identity")
	}
	width := bits / 8
	if err := c.validateFPVectorSpan(destination.FPOffset, width); err != nil {
		return context(err.Error())
	}
	if c.classicFrame != "" {
		return nil
	}
	slot, _, ok := c.fpVectorSlot(destination.FPOffset)
	if !ok || slot.Offset != destination.FPOffset || x86FrameTypeSize(slot.Type) < int64(width) {
		return context("native access is not an existing complete contiguous shadow slot")
	}
	return nil
}

func (c *amd64Ctx) compareExchangeJoinPair(low, high string, bits int) string {
	partType := LLVMType("i32")
	pairType := LLVMType("i64")
	shift := 32
	if bits == 128 {
		partType = I64
		pairType = LLVMType("i128")
		shift = 64
	}
	lowPart, highPart := low, high
	if partType == I32 {
		lowPart = c.truncI64(low, I32)
		highPart = c.truncI64(high, I32)
	}
	lowWide := c.newTmp()
	highWide := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", lowWide, partType, lowPart, pairType)
	fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", highWide, partType, highPart, pairType)
	shifted := c.newTmp()
	joined := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shl %s %%%s, %d\n", shifted, pairType, highWide, shift)
	fmt.Fprintf(c.b, "  %%%s = or %s %%%s, %%%s\n", joined, pairType, shifted, lowWide)
	return "%" + joined
}

func (c *amd64Ctx) compareExchangeSplitPair(pair string, bits int) (low, high string) {
	pairType := LLVMType("i64")
	partType := LLVMType("i32")
	shift := 32
	if bits == 128 {
		pairType = LLVMType("i128")
		partType = I64
		shift = 64
	}
	lowName := c.newTmp()
	highShift := c.newTmp()
	highName := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc %s %s to %s\n", lowName, pairType, pair, partType)
	fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %d\n", highShift, pairType, pair, shift)
	fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", highName, pairType, highShift, partType)
	return "%" + lowName, "%" + highName
}

func (c *amd64Ctx) storeCompareExchangePairAccumulator(reg Reg, original, failurePart, success string, bits int) error {
	failure64 := failurePart
	if bits == 64 {
		widened := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", widened, failurePart)
		failure64 = "%" + widened
	}
	selected := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i64 %s, i64 %s\n", selected, success, original, failure64)
	return c.storeReg(reg, "%"+selected)
}

func (c *amd64Ctx) compareExchangePointer(destination Operand) (ptr, ptrType string, err error) {
	switch destination.Kind {
	case OpMem:
		return c.ptrFromMem(destination.Mem)
	case OpSym:
		ptr, err := c.ptrFromSB(destination.Sym)
		return ptr, "ptr", err
	case OpFP:
		if c.classicFrame != "" {
			return c.classicFramePtr(destination.FPOffset), "ptr", nil
		}
		if ptr := c.fpParamAlloca[destination.FPOffset]; ptr != "" {
			return ptr, "ptr", nil
		}
		if ptr, _, ok := c.fpResultAlloca(destination.FPOffset); ok {
			return ptr, "ptr", nil
		}
		return "", "", fmt.Errorf("CMPXCHG FP operand has no mutable slot at +%d(FP)", destination.FPOffset)
	default:
		return "", "", fmt.Errorf("CMPXCHG expected memory destination, got %s", destination.String())
	}
}
