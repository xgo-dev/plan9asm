package plan9asm

import (
	"fmt"
	"strings"
)

// lowerCompareExchange implements every operand row in Go 1.27's yrb_mb,
// yrl_ml, and yscond tables for the CMPXCHG family.
func (c *amd64Ctx) lowerCompareExchange(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	kind, bits, recognized := amd64CompareExchangeProperties(baseOp)
	if !recognized {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	if c.goarch == "386" && (bits == 64 && kind == "scalar" || bits == 128) {
		return true, false, fmt.Errorf("386 %s is illegal in 32-bit mode: %q", baseOp, ins.Raw)
	}

	switch kind {
	case "scalar":
		return c.lowerScalarCompareExchange(baseOp, bits, ins)
	case "pair":
		return c.lowerPairCompareExchange(baseOp, bits, ins)
	default:
		return true, false, fmt.Errorf("internal error: unknown CMPXCHG kind %q", kind)
	}
}

func amd64CompareExchangeProperties(op string) (kind string, bits int, ok bool) {
	switch op {
	case "CMPXCHGB":
		return "scalar", 8, true
	case "CMPXCHGW":
		return "scalar", 16, true
	case "CMPXCHGL":
		return "scalar", 32, true
	case "CMPXCHGQ":
		return "scalar", 64, true
	case "CMPXCHG8B":
		return "pair", 64, true
	case "CMPXCHG16B":
		return "pair", 128, true
	default:
		return "", 0, false
	}
}

func (c *amd64Ctx) lowerScalarCompareExchange(baseOp string, bits int, ins Instr) (bool, bool, error) {
	if len(ins.Args) != 2 {
		return true, false, fmt.Errorf("%s %s expects register source and register/memory destination: %q", c.goarch, baseOp, ins.Raw)
	}
	registerAllowed := func(reg Reg) bool {
		if bits == 8 {
			return isGoYmbRegisterForArch(reg, c.goarch)
		}
		return isX86YrlRegisterForArch(reg, c.goarch)
	}
	source, destination := ins.Args[0], ins.Args[1]
	if source.Kind != OpReg || !registerAllowed(source.Reg) {
		return true, false, fmt.Errorf("%s %s source is outside Go 1.27's Yrb/Yrl class: %q", c.goarch, baseOp, ins.Raw)
	}
	if destination.Kind == OpReg {
		if !registerAllowed(destination.Reg) {
			return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's Ymb/Yml class: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(destination) {
		return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's Ymb/Yml class: %q", c.goarch, baseOp, ins.Raw)
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
		align := bits / 8
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = cmpxchg %s %s, %s %s, %s %s seq_cst seq_cst, align %d\n", result, ptrType, ptr, typ, expected, typ, desired, align)
		oldName := c.newTmp()
		successName := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue { %s, i1 } %%%s, 0\n", oldName, typ, result)
		fmt.Fprintf(c.b, "  %%%s = extractvalue { %s, i1 } %%%s, 1\n", successName, typ, result)
		old, success = "%"+oldName, "%"+successName
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
	if len(ins.Args) != 1 {
		return true, false, fmt.Errorf("%s %s expects one Ymb register/memory operand: %q", c.goarch, baseOp, ins.Raw)
	}
	destination := ins.Args[0]
	if destination.Kind == OpReg {
		if !isGoYmbRegisterForArch(destination.Reg, c.goarch) {
			return true, false, fmt.Errorf("%s %s operand is outside Go 1.27's Ymb class: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(destination) {
		return true, false, fmt.Errorf("%s %s operand is outside Go 1.27's Ymb class: %q", c.goarch, baseOp, ins.Raw)
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
	expected := c.compareExchangeJoinPair(ax, dx, bits)
	desired := c.compareExchangeJoinPair(bx, cx, bits)
	pairType := LLVMType("i64")
	align := 8
	if bits == 128 {
		pairType = LLVMType("i128")
		align = 16
	}

	var old, success string
	if destination.Kind == OpReg {
		base, _, _ := amd64ByteRegBase(destination.Reg)
		old64, err := c.loadReg(base)
		if err != nil {
			return true, false, err
		}
		old = old64
		if bits == 128 {
			widened := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i64 %s to i128\n", widened, old64)
			old = "%" + widened
		}
		equal := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, %s\n", equal, pairType, expected, old)
		success = "%" + equal
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, %s %s, %s %s\n", selected, success, pairType, desired, pairType, old)
		selected64 := "%" + selected
		if bits == 128 {
			truncated := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i128 %%%s to i64\n", truncated, selected)
			selected64 = "%" + truncated
		}
		if err := c.storeReg(base, selected64); err != nil {
			return true, false, err
		}
	} else {
		ptr, ptrType, err := c.compareExchangePointer(destination)
		if err != nil {
			return true, false, err
		}
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = cmpxchg %s %s, %s %s, %s %s seq_cst seq_cst, align %d\n", result, ptrType, ptr, pairType, expected, pairType, desired, align)
		oldName := c.newTmp()
		successName := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue { %s, i1 } %%%s, 0\n", oldName, pairType, result)
		fmt.Fprintf(c.b, "  %%%s = extractvalue { %s, i1 } %%%s, 1\n", successName, pairType, result)
		old, success = "%"+oldName, "%"+successName
	}

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
