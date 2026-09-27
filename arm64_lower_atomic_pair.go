package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

func (c *arm64Ctx) lowerAtomicPair(op Op, ins Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "CASPW", "CASPD":
		if arm64AtomicOpcodeHasSuffix(ins.Op) {
			return true, false, fmt.Errorf("arm64 %s does not accept an opcode suffix: %q", op, ins.Raw)
		}
		if len(ins.Args) != 3 || !arm64AtomicRegisterPair(ins.Args[0]) || ins.Args[1].Kind != OpMem || !arm64AtomicRegisterPair(ins.Args[2]) {
			return true, false, fmt.Errorf("arm64 %s expects register-pair, zero-offset memory, register-pair: %q", op, ins.Raw)
		}
		expectedRegs := ins.Args[0].RegList
		newRegs := ins.Args[2].RegList
		if err := validateARM64CASPRegisterPair("source", expectedRegs); err != nil {
			return true, false, fmt.Errorf("arm64 %s: %w: %q", op, err, ins.Raw)
		}
		if err := validateARM64CASPRegisterPair("destination", newRegs); err != nil {
			return true, false, fmt.Errorf("arm64 %s: %w: %q", op, err, ins.Raw)
		}
		ptr, err := c.atomicPairMemPtr(ins.Args[1].Mem, true)
		if err != nil {
			return true, false, fmt.Errorf("arm64 %s: %w: %q", op, err, ins.Raw)
		}

		elemBits := 32
		if op == "CASPD" {
			elemBits = 64
		}
		return true, false, c.lowerAtomicPairCompareExchange(expectedRegs, newRegs, elemBits, ptr, "seq_cst", "seq_cst")

	case "LDXPW", "LDXP", "LDAXPW", "LDAXP":
		if arm64AtomicOpcodeHasSuffix(ins.Op) {
			return true, false, fmt.Errorf("arm64 %s does not accept an opcode suffix: %q", op, ins.Raw)
		}
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpMem || !arm64AtomicRegisterPair(ins.Args[1]) {
			return true, false, fmt.Errorf("arm64 %s expects zero-offset memory, register-pair: %q", op, ins.Raw)
		}
		regs := ins.Args[1].RegList
		if err := validateARM64ExclusiveLoadPair(regs); err != nil {
			return true, false, fmt.Errorf("arm64 %s: %w: %q", op, err, ins.Raw)
		}
		ptr, err := c.atomicPairMemPtr(ins.Args[0].Mem, false)
		if err != nil {
			return true, false, fmt.Errorf("arm64 %s: %w: %q", op, err, ins.Raw)
		}
		elemBits := 32
		typeName := "i64"
		align := 8
		if op == "LDXP" || op == "LDAXP" {
			elemBits = 64
			typeName = "i128"
			align = 16
		}
		loaded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load atomic %s, ptr %s seq_cst, align %d\n", loaded, typeName, ptr, align)
		if err := c.storeAtomicPairValue(regs, elemBits, "%"+loaded); err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  store i1 true, ptr %s\n", c.exclusiveValidSlot)
		fmt.Fprintf(c.b, "  store ptr %s, ptr %s\n", ptr, c.exclusivePtrSlot)
		fmt.Fprintf(c.b, "  store i8 %d, ptr %s\n", align, c.exclusiveSizeSlot)
		reserved, err := c.atomicPairValueAsI128("%"+loaded, typeName)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  store i128 %s, ptr %s\n", reserved, c.exclusiveValueSlot)
		return true, false, nil

	case "STXPW", "STXP", "STLXPW", "STLXP":
		if arm64AtomicOpcodeHasSuffix(ins.Op) {
			return true, false, fmt.Errorf("arm64 %s does not accept an opcode suffix: %q", op, ins.Raw)
		}
		if len(ins.Args) != 3 || !arm64AtomicRegisterPair(ins.Args[0]) || ins.Args[1].Kind != OpMem || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 %s expects register-pair, zero-offset memory, status-register: %q", op, ins.Raw)
		}
		regs := ins.Args[0].RegList
		status := ins.Args[2].Reg
		if err := validateARM64ExclusiveStorePair(regs, ins.Args[1].Mem.Base, status); err != nil {
			return true, false, fmt.Errorf("arm64 %s: %w: %q", op, err, ins.Raw)
		}
		ptr, err := c.atomicPairMemPtr(ins.Args[1].Mem, false)
		if err != nil {
			return true, false, fmt.Errorf("arm64 %s: %w: %q", op, err, ins.Raw)
		}
		elemBits := 32
		typeName := "i64"
		align := 8
		if op == "STXP" || op == "STLXP" {
			elemBits = 64
			typeName = "i128"
			align = 16
		}
		newValue, err := c.loadAtomicPairValue(regs, elemBits)
		if err != nil {
			return true, false, err
		}
		statusValue, err := c.lowerAtomicPairExclusiveStore(typeName, align, ptr, newValue)
		if err != nil {
			return true, false, err
		}
		return true, false, c.storeReg(status, statusValue)
	}
	return false, false, nil
}

func (c *arm64Ctx) lowerAtomicPairCompareExchange(expectedRegs, newRegs []Reg, elemBits int, ptr, successOrder, failureOrder string) error {
	typeName := "i64"
	align := 8
	if elemBits == 64 {
		typeName = "i128"
		align = 16
	} else if elemBits != 32 {
		return fmt.Errorf("arm64: invalid CASP element width %d", elemBits)
	}
	expected, err := c.loadAtomicPairValue(expectedRegs, elemBits)
	if err != nil {
		return err
	}
	newValue, err := c.loadAtomicPairValue(newRegs, elemBits)
	if err != nil {
		return err
	}
	cx := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = cmpxchg ptr %s, %s %s, %s %s %s %s, align %d\n",
		cx, ptr, typeName, expected, typeName, newValue, successOrder, failureOrder, align)
	old := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractvalue {%s, i1} %%%s, 0\n", old, typeName, cx)
	return c.storeAtomicPairValue(expectedRegs, elemBits, "%"+old)
}

func arm64AtomicOpcodeHasSuffix(op Op) bool {
	return strings.Contains(string(op), ".")
}

func arm64AtomicRegisterPair(op Operand) bool {
	return op.Kind == OpRegList && len(op.RegList) == 2
}

func arm64AtomicDataRegister(reg Reg) bool {
	s := strings.ToUpper(string(reg))
	if s == "ZR" || s == "RSP" {
		return true
	}
	if !strings.HasPrefix(s, "R") {
		return false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(s, "R"))
	return err == nil && n >= 0 && n <= 30
}

func arm64AtomicNumberedRegister(reg Reg) (int, bool) {
	s := strings.ToUpper(string(reg))
	if !strings.HasPrefix(s, "R") || s == "RSP" {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(s, "R"))
	return n, err == nil && n >= 0 && n <= 30
}

func validateARM64CASPRegisterPair(role string, regs []Reg) error {
	if len(regs) != 2 || !arm64AtomicDataRegister(regs[0]) || !arm64AtomicDataRegister(regs[1]) {
		return fmt.Errorf("%s must be a pair of general-purpose registers", role)
	}
	first, ok := arm64AtomicNumberedRegister(regs[0])
	if !ok || first&1 != 0 {
		return fmt.Errorf("%s register pair must start from an even numbered register", role)
	}
	wantSecond := Reg(fmt.Sprintf("R%d", first+1))
	if first == 30 {
		wantSecond = ZR
	}
	if regs[1] != wantSecond {
		return fmt.Errorf("%s register pair must be contiguous", role)
	}
	return nil
}

func validateARM64ExclusiveLoadPair(regs []Reg) error {
	if len(regs) != 2 || !arm64AtomicDataRegister(regs[0]) || !arm64AtomicDataRegister(regs[1]) {
		return fmt.Errorf("destination must be a pair of general-purpose registers")
	}
	if regs[0] == regs[1] {
		return fmt.Errorf("destination register pair has constrained unpredictable behavior")
	}
	return nil
}

func validateARM64ExclusiveStorePair(regs []Reg, base Reg, status Reg) error {
	if len(regs) != 2 || !arm64AtomicDataRegister(regs[0]) || !arm64AtomicDataRegister(regs[1]) {
		return fmt.Errorf("source must be a pair of general-purpose registers")
	}
	if !arm64AtomicStatusRegister(status) {
		return fmt.Errorf("status must be a general-purpose register or ZR")
	}
	if status == regs[0] || status == regs[1] || (base != Reg("RSP") && status == base) {
		return fmt.Errorf("status register overlap has constrained unpredictable behavior")
	}
	return nil
}

func arm64AtomicStatusRegister(reg Reg) bool {
	if reg == ZR {
		return true
	}
	_, ok := arm64AtomicNumberedRegister(reg)
	return ok
}

func (c *arm64Ctx) atomicPairMemPtr(mem MemRef, allowNamedSP bool) (string, error) {
	if mem.Sym != "" || mem.Segment != "" || mem.Index != "" || mem.Off != 0 {
		return "", fmt.Errorf("paired atomic memory must have zero displacement and no index")
	}
	if mem.OffRaw != "" {
		if !allowNamedSP || mem.Base != SP {
			return "", fmt.Errorf("named SP memory is only accepted by CASP")
		}
	} else if mem.Base == SP {
		return "", fmt.Errorf("plain SP is a pseudo-register; use RSP for register-relative memory")
	}
	if mem.Base != SP && mem.Base != Reg("RSP") && mem.Base != ZR {
		if _, ok := arm64AtomicNumberedRegister(mem.Base); !ok {
			return "", fmt.Errorf("paired atomic memory base must be R0-R30, RSP, or ZR")
		}
	}
	return c.atomicMemPtr(mem)
}

func (c *arm64Ctx) loadAtomicPairDataReg(reg Reg) (string, error) {
	if reg == ZR || reg == Reg("RSP") {
		return "0", nil
	}
	return c.loadReg(reg)
}

func (c *arm64Ctx) storeAtomicPairDataReg(reg Reg, value string) error {
	if reg == ZR || reg == Reg("RSP") {
		return nil
	}
	return c.storeReg(reg, value)
}

func (c *arm64Ctx) loadAtomicPairValue(regs []Reg, elemBits int) (string, error) {
	low64, err := c.loadAtomicPairDataReg(regs[0])
	if err != nil {
		return "", err
	}
	high64, err := c.loadAtomicPairDataReg(regs[1])
	if err != nil {
		return "", err
	}
	if elemBits == 32 {
		low32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", low32, low64)
		low := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", low, low32)
		high32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", high32, high64)
		high := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", high, high32)
		shifted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl i64 %%%s, 32\n", shifted, high)
		joined := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %%%s\n", joined, low, shifted)
		return "%" + joined, nil
	}
	if elemBits != 64 {
		return "", fmt.Errorf("arm64: invalid atomic pair element width %d", elemBits)
	}
	low := c.newTmp()
	msg := "  %%%s = zext i64 %s to i128\n"
	fmt.Fprintf(c.b, msg, low, low64)
	high := c.newTmp()
	fmt.Fprintf(c.b, msg, high, high64)
	shifted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shl i128 %%%s, 64\n", shifted, high)
	joined := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = or i128 %%%s, %%%s\n", joined, low, shifted)
	return "%" + joined, nil
}

func (c *arm64Ctx) storeAtomicPairValue(regs []Reg, elemBits int, value string) error {
	if elemBits == 32 {
		low32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", low32, value)
		low64 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", low64, low32)
		highShift := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, 32\n", highShift, value)
		high32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", high32, highShift)
		high64 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", high64, high32)
		if err := c.storeAtomicPairDataReg(regs[0], "%"+low64); err != nil {
			return err
		}
		return c.storeAtomicPairDataReg(regs[1], "%"+high64)
	}
	if elemBits != 64 {
		return fmt.Errorf("arm64: invalid atomic pair element width %d", elemBits)
	}
	low := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i128 %s to i64\n", low, value)
	highShift := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = lshr i128 %s, 64\n", highShift, value)
	high := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i128 %%%s to i64\n", high, highShift)
	if err := c.storeAtomicPairDataReg(regs[0], "%"+low); err != nil {
		return err
	}
	return c.storeAtomicPairDataReg(regs[1], "%"+high)
}

func (c *arm64Ctx) atomicPairValueAsI128(value, typeName string) (string, error) {
	if typeName == "i128" {
		return value, nil
	}
	if typeName != "i64" {
		return "", fmt.Errorf("arm64: invalid paired atomic value type %s", typeName)
	}
	extended := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i64 %s to i128\n", extended, value)
	return "%" + extended, nil
}

func (c *arm64Ctx) lowerAtomicPairExclusiveStore(typeName string, align int, ptr, newValue string) (string, error) {
	loadedValid := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", loadedValid, c.exclusiveValidSlot)
	loadedPtr := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load ptr, ptr %s\n", loadedPtr, c.exclusivePtrSlot)
	ptrMatch := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq ptr %%%s, %s\n", ptrMatch, loadedPtr, ptr)
	loadedSize := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i8, ptr %s\n", loadedSize, c.exclusiveSizeSlot)
	sizeMatch := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i8 %%%s, %d\n", sizeMatch, loadedSize, align)
	precondition := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", precondition, loadedValid, ptrMatch)
	canTry := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", canTry, precondition, sizeMatch)

	id := c.newTmp()
	tryLabel := arm64LLVMBlockName("stxp_try_" + id)
	failLabel := arm64LLVMBlockName("stxp_fail_" + id)
	mergeLabel := arm64LLVMBlockName("stxp_merge_" + id)
	fmt.Fprintf(c.b, "  br i1 %%%s, label %%%s, label %%%s\n", canTry, tryLabel, failLabel)

	fmt.Fprintf(c.b, "\n%s:\n", tryLabel)
	expected128 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i128, ptr %s\n", expected128, c.exclusiveValueSlot)
	expected := "%" + expected128
	if typeName == "i64" {
		truncated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i128 %%%s to i64\n", truncated, expected128)
		expected = "%" + truncated
	} else if typeName != "i128" {
		return "", fmt.Errorf("arm64: invalid paired atomic store type %s", typeName)
	}
	cx := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = cmpxchg ptr %s, %s %s, %s %s seq_cst seq_cst, align %d\n", cx, ptr, typeName, expected, typeName, newValue, align)
	succeeded := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractvalue {%s, i1} %%%s, 1\n", succeeded, typeName, cx)
	failed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", failed, succeeded)
	tryStatus := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i1 %%%s to i64\n", tryStatus, failed)
	fmt.Fprintf(c.b, "  br label %%%s\n", mergeLabel)

	fmt.Fprintf(c.b, "\n%s:\n", failLabel)
	fmt.Fprintf(c.b, "  br label %%%s\n", mergeLabel)

	fmt.Fprintf(c.b, "\n%s:\n", mergeLabel)
	status := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = phi i64 [ %%%s, %%%s ], [ 1, %%%s ]\n", status, tryStatus, tryLabel, failLabel)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.exclusiveValidSlot)
	return "%" + status, nil
}
