package plan9asm

import (
	"fmt"

	"github.com/xgo-dev/plan9asm/internal/arm64atomic"
)

var (
	arm64AtomicWidthType = [...]LLVMType{I8, I16, I32, I64}
	arm64AtomicOrdering  = [...]string{"monotonic", "release", "acquire", "acq_rel"}
)

func decodeARM64LSEScalarWord(word uint32, original Instr) (Instr, bool) {
	opcode, ok := arm64atomic.DecodeLSE(word)
	if !ok {
		return Instr{}, false
	}
	register := func(n uint32, reg31 Reg) Reg {
		if n == 31 {
			return reg31
		}
		return Reg(fmt.Sprintf("R%d", n))
	}
	return Instr{
		Op: Op(opcode),
		Args: []Operand{
			{Kind: OpReg, Reg: register(word>>16&31, ZR)},
			{Kind: OpMem, Mem: MemRef{Base: register(word>>5&31, "RSP")}},
			{Kind: OpReg, Reg: register(word&31, ZR)},
		},
		Raw: original.Raw, arm64Encoded: true,
	}, true
}

func (c *arm64Ctx) lowerAtomic(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if ok, terminated, err := c.lowerAtomicPair(op, ins); ok {
		return ok, terminated, err
	}
	if form, matched := arm64atomic.Lookup(string(op), ins.arm64Encoded); matched {
		ty := arm64AtomicWidthType[form.Size]
		switch form.Kind {
		case arm64atomic.ReadModifyWrite:
			return true, false, c.lowerAtomicRMWFamily(form, ty, ins)
		case arm64atomic.CompareExchange:
			return true, false, c.lowerAtomicCASFamily(form, ty, ins)
		case arm64atomic.LoadExclusive, arm64atomic.StoreExclusive:
			return true, false, c.lowerExclusiveFamily(form, ty, ins)
		case arm64atomic.LoadOrdered, arm64atomic.StoreOrdered:
			return true, false, c.lowerOrderedAtomicMemory(ins, ty, form.Kind == arm64atomic.LoadOrdered)
		}
	}
	switch op {
	case "CLREX":
		if arm64AtomicOpcodeHasSuffix(ins.Op) || len(ins.Args) > 1 || len(ins.Args) == 1 && ins.Args[0].Kind != OpImm {
			return true, false, fmt.Errorf("arm64 CLREX expects no operand or one immediate: %q", ins.Raw)
		}
		// LLVM IR has no exposed exclusive-monitor primitive. The ARM64
		// backend models LDXR/STXR reservations explicitly, so clearing the
		// validity bit implements both Go assembler forms exactly. The
		// optional architectural immediate is only an implementation hint.
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.exclusiveValidSlot)
		return true, false, nil
	}
	return false, false, nil
}

func (c *arm64Ctx) lowerOrderedAtomicMemory(ins Instr, ty LLVMType, load bool) error {
	memoryIndex := 1
	if load {
		memoryIndex = 0
	}
	mem, err := arm64ScalarAtomicMemory(ins, memoryIndex, 2)
	if err != nil {
		return err
	}
	align, err := arm64AtomicTypeSize(ty)
	if err != nil {
		return err
	}
	ptr, err := c.atomicMemPtr(mem)
	if err != nil {
		return err
	}
	if load {
		ld := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load atomic %s, ptr %s acquire, align %d\n", ld, ty, ptr, align)
		value, err := c.atomicExtendToI64("%"+ld, ty)
		if err != nil {
			return err
		}
		return c.storeReg(ins.Args[1].Reg, value)
	}
	src, err := c.loadRegisterWidth(ins.Args[0].Reg, align*8)
	if err != nil {
		return err
	}
	value, err := c.atomicTruncFromI64(src, ty)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.b, "  store atomic %s %s, ptr %s release, align %d\n", ty, value, ptr, align)
	return nil
}

func arm64LSEOutputOrdering(order arm64atomic.Order, output Reg) arm64atomic.Order {
	// CAS returns the old value in its first operand (Rs), whereas the
	// arithmetic/swap families return it in their final operand (Rt).
	if output == ZR {
		return order &^ arm64atomic.Acquire
	}
	return order
}

func (c *arm64Ctx) lowerAtomicRMWFamily(form arm64atomic.Form, ty LLVMType, ins Instr) error {
	mem, err := arm64ScalarAtomicMemory(ins, 1, 3)
	if err != nil {
		return err
	}
	source64, err := c.loadRegisterWidth(ins.Args[0].Reg, arm64MachineScalarWidth(ty))
	if err != nil {
		return err
	}
	source, err := c.atomicTruncFromI64(source64, ty)
	if err != nil {
		return err
	}
	argument := source
	if form.Invert {
		inverted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, -1\n", inverted, ty, source)
		argument = "%" + inverted
	}
	pointer, err := c.atomicMemPtr(mem)
	if err != nil {
		return err
	}
	old := c.newTmp()
	order := arm64LSEOutputOrdering(form.Order, ins.Args[2].Reg)
	fmt.Fprintf(c.b, "  %%%s = atomicrmw %s ptr %s, %s %s %s\n",
		old, form.Operation, pointer, ty, argument, arm64AtomicOrdering[order])
	old64, err := c.atomicExtendToI64("%"+old, ty)
	if err != nil {
		return err
	}
	return c.storeReg(ins.Args[2].Reg, old64)
}

func (c *arm64Ctx) lowerAtomicCASFamily(form arm64atomic.Form, ty LLVMType, ins Instr) error {
	mem, err := arm64ScalarAtomicMemory(ins, 1, 3)
	if err != nil {
		return err
	}
	width := arm64MachineScalarWidth(ty)
	expected64, err := c.loadRegisterWidth(ins.Args[0].Reg, width)
	if err != nil {
		return err
	}
	expected, err := c.atomicTruncFromI64(expected64, ty)
	if err != nil {
		return err
	}
	new64, err := c.loadRegisterWidth(ins.Args[2].Reg, width)
	if err != nil {
		return err
	}
	newValue, err := c.atomicTruncFromI64(new64, ty)
	if err != nil {
		return err
	}
	pointer, err := c.atomicMemPtr(mem)
	if err != nil {
		return err
	}
	align, err := arm64AtomicTypeSize(ty)
	if err != nil {
		return err
	}
	changed := c.newTmp()
	order := arm64LSEOutputOrdering(form.Order, ins.Args[0].Reg)
	fmt.Fprintf(c.b, "  %%%s = cmpxchg ptr %s, %s %s, %s %s %s %s, align %d\n",
		changed, pointer, ty, expected, ty, newValue,
		arm64AtomicOrdering[order], arm64AtomicOrdering[order&arm64atomic.Acquire], align)
	old := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractvalue {%s, i1} %%%s, 0\n", old, ty, changed)
	old64, err := c.atomicExtendToI64("%"+old, ty)
	if err != nil {
		return err
	}
	return c.storeReg(ins.Args[0].Reg, old64)
}

func (c *arm64Ctx) lowerExclusiveFamily(form arm64atomic.Form, ty LLVMType, ins Instr) error {
	memoryIndex, wantArgs := 1, 3
	isLoad := form.Kind == arm64atomic.LoadExclusive
	if isLoad {
		memoryIndex, wantArgs = 0, 2
	}
	mem, err := arm64ScalarAtomicMemory(ins, memoryIndex, wantArgs)
	if err != nil {
		return err
	}
	pointer, err := c.atomicMemPtr(mem)
	if err != nil {
		return err
	}
	size, err := arm64AtomicTypeSize(ty)
	if err != nil {
		return err
	}
	if isLoad {
		loaded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load atomic %s, ptr %s %s, align %d\n", loaded, ty, pointer, arm64AtomicOrdering[form.Order], size)
		value64, err := c.atomicExtendToI64("%"+loaded, ty)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store i1 true, ptr %s\n", c.exclusiveValidSlot)
		fmt.Fprintf(c.b, "  store ptr %s, ptr %s\n", pointer, c.exclusivePtrSlot)
		fmt.Fprintf(c.b, "  store i8 %d, ptr %s\n", size, c.exclusiveSizeSlot)
		fmt.Fprintf(c.b, "  store i64 %s, ptr %s\n", value64, c.exclusiveValueSlot)
		return c.storeReg(ins.Args[1].Reg, value64)
	}
	source64, err := c.loadReg(ins.Args[0].Reg)
	if err != nil {
		return err
	}
	newValue, err := c.atomicTruncFromI64(source64, ty)
	if err != nil {
		return err
	}
	loadedValid := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", loadedValid, c.exclusiveValidSlot)
	loadedPointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load ptr, ptr %s\n", loadedPointer, c.exclusivePtrSlot)
	pointerMatches := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq ptr %%%s, %s\n", pointerMatches, loadedPointer, pointer)
	loadedSize := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i8, ptr %s\n", loadedSize, c.exclusiveSizeSlot)
	sizeMatches := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i8 %%%s, %d\n", sizeMatches, loadedSize, size)
	validPointer := c.newTmp()
	canTry := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", validPointer, loadedValid, pointerMatches)
	fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", canTry, validPointer, sizeMatches)
	id := c.newTmp()
	tryLabel := arm64LLVMBlockName("stxr_try_" + id)
	failLabel := arm64LLVMBlockName("stxr_fail_" + id)
	mergeLabel := arm64LLVMBlockName("stxr_merge_" + id)
	fmt.Fprintf(c.b, "  br i1 %%%s, label %%%s, label %%%s\n", canTry, tryLabel, failLabel)
	fmt.Fprintf(c.b, "\n%s:\n", tryLabel)
	expected64 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s\n", expected64, c.exclusiveValueSlot)
	expected, err := c.atomicTruncFromI64("%"+expected64, ty)
	if err != nil {
		return err
	}
	changed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = cmpxchg ptr %s, %s %s, %s %s %s %s, align %d\n",
		changed, pointer, ty, expected, ty, newValue, arm64AtomicOrdering[form.Order], arm64AtomicOrdering[arm64atomic.Relaxed], size)
	succeeded := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractvalue {%s, i1} %%%s, 1\n", succeeded, ty, changed)
	failed := c.newTmp()
	tryStatus := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", failed, succeeded)
	fmt.Fprintf(c.b, "  %%%s = zext i1 %%%s to i64\n", tryStatus, failed)
	fmt.Fprintf(c.b, "  br label %%%s\n", mergeLabel)
	fmt.Fprintf(c.b, "\n%s:\n", failLabel)
	fmt.Fprintf(c.b, "  br label %%%s\n", mergeLabel)
	fmt.Fprintf(c.b, "\n%s:\n", mergeLabel)
	status := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = phi i64 [ %%%s, %%%s ], [ 1, %%%s ]\n", status, tryStatus, tryLabel, failLabel)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.exclusiveValidSlot)
	return c.storeReg(ins.Args[2].Reg, "%"+status)
}

func (c *arm64Ctx) atomicMemPtr(mem MemRef) (string, error) {
	addr, _, _, err := c.addrI64(mem, false)
	if err != nil {
		return "", err
	}
	pt := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pt, addr)
	return "%" + pt, nil
}

func arm64ScalarAtomicMemory(ins Instr, memoryIndex, wantArgs int) (MemRef, error) {
	fail := func() (MemRef, error) {
		return MemRef{}, fmt.Errorf("arm64 %s requires general or zero registers and one zero-offset register address: %q", ins.Op, ins.Raw)
	}
	if arm64AtomicOpcodeHasSuffix(ins.Op) || len(ins.Args) != wantArgs {
		return fail()
	}
	for index, argument := range ins.Args {
		if index != memoryIndex && (argument.Kind != OpReg || !isARM64GeneralOrZeroReg(argument.Reg)) {
			return fail()
		}
	}
	argument := ins.Args[memoryIndex]
	mem := argument.Mem
	if argument.Kind != OpMem || mem != (MemRef{Base: mem.Base}) ||
		(mem.Base != "RSP" && !isARM64GeneralOrZeroReg(mem.Base)) {
		return fail()
	}
	if mem.Base == "RSP" || mem.Base == ZR {
		mem.Base = SP // Encoding 31 is SP only in the address bank.
	}
	return mem, nil
}

func arm64AtomicTypeSize(ty LLVMType) (int, error) {
	switch ty {
	case I8:
		return 1, nil
	case I16:
		return 2, nil
	case I32:
		return 4, nil
	case I64:
		return 8, nil
	default:
		return 0, fmt.Errorf("arm64: unsupported atomic type size for %s", ty)
	}
}

func (c *arm64Ctx) atomicTruncFromI64(v64 string, ty LLVMType) (string, error) {
	switch ty {
	case I64:
		return v64, nil
	case I32, I16, I8, I1:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", t, v64, ty)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("arm64: unsupported trunc target %s", ty)
	}
}

func (c *arm64Ctx) atomicExtendToI64(v string, ty LLVMType) (string, error) {
	switch ty {
	case I64:
		return v, nil
	case I32, I16, I8, I1:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext %s %s to i64\n", t, ty, v)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("arm64: unsupported extend source %s", ty)
	}
}
