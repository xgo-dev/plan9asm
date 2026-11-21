package plan9asm

import (
	"fmt"
	"strings"
)

type arm64AtomicRMWForm struct {
	typeName  LLVMType
	operation string
	order     uint32
	invert    bool
}

type arm64AtomicRMWSpec struct {
	stem      string
	operation string
	invert    bool
}

// Indexed by the LSE o3:opc field. The same Go encoder rows use every
// width and both independent acquire/release bits for each operation.
var arm64AtomicRMWSpecs = [...]arm64AtomicRMWSpec{
	0: {"LDADD", "add", false},
	1: {"LDCLR", "and", true},
	2: {"LDEOR", "xor", false},
	3: {"LDOR", "or", false},
	8: {"SWP", "xchg", false},
}

const (
	arm64AtomicWidthSuffix = "BHWD"
	arm64AtomicAcquireBit  = 2
)

var (
	arm64AtomicWidthType   = [...]LLVMType{I8, I16, I32, I64}
	arm64AtomicOrderSuffix = [...]string{"", "L", "A", "AL"}
	arm64AtomicOrdering    = [...]string{"monotonic", "release", "acquire", "acq_rel"}
)

type arm64AtomicCASForm struct {
	typeName LLVMType
	order    uint32
}

type arm64ExclusiveForm struct {
	typeName     LLVMType
	isLoad       bool
	successOrder string
	failureOrder string
}

func parseARM64ExclusiveOpcode(op Op) (arm64ExclusiveForm, bool) {
	name := strings.ToUpper(string(op))
	form := arm64ExclusiveForm{failureOrder: "monotonic"}
	prefix := ""
	switch {
	case strings.HasPrefix(name, "LDAXR"):
		prefix, form.isLoad, form.successOrder = "LDAXR", true, "acquire"
	case strings.HasPrefix(name, "LDXR"):
		prefix, form.isLoad, form.successOrder = "LDXR", true, "monotonic"
	case strings.HasPrefix(name, "STLXR"):
		prefix, form.successOrder = "STLXR", "release"
	case strings.HasPrefix(name, "STXR"):
		prefix, form.successOrder = "STXR", "monotonic"
	default:
		return arm64ExclusiveForm{}, false
	}
	ty, matched := arm64AtomicGoWidth(name[len(prefix):])
	form.typeName = ty
	return form, matched
}

// Unlike LSE read-modify-write instructions, ordered and exclusive loads and
// stores spell the doubleword form with no width suffix.
func arm64AtomicGoWidth(suffix string) (LLVMType, bool) {
	if suffix == "" {
		return I64, true
	}
	if len(suffix) == 1 {
		if size := strings.IndexByte(arm64AtomicWidthSuffix[:3], suffix[0]); size >= 0 {
			return arm64AtomicWidthType[size], true
		}
	}
	return "", false
}

func parseARM64AtomicLoadStoreOpcode(op Op) (LLVMType, bool, bool) {
	name := string(op)
	if strings.HasPrefix(name, "LDAR") {
		ty, matched := arm64AtomicGoWidth(name[4:])
		return ty, true, matched
	}
	if strings.HasPrefix(name, "STLR") {
		ty, matched := arm64AtomicGoWidth(name[4:])
		return ty, false, matched
	}
	return "", false, false
}

func arm64AtomicLSEFormat(format string) (size, order uint32, ok bool) {
	if format == "" {
		return 0, 0, false
	}
	width := strings.IndexByte(arm64AtomicWidthSuffix, format[len(format)-1])
	if width < 0 {
		return 0, 0, false
	}
	ordering := format[:len(format)-1]
	for index, suffix := range arm64AtomicOrderSuffix {
		if ordering == suffix {
			return uint32(width), uint32(index), true
		}
	}
	return 0, 0, false
}

func parseARM64AtomicCASOpcode(op Op, encoded bool) (arm64AtomicCASForm, bool) {
	format, found := strings.CutPrefix(strings.ToUpper(string(op)), "CAS")
	if !found {
		return arm64AtomicCASForm{}, false
	}
	size, order, matched := arm64AtomicLSEFormat(format)
	// Go's CAS byte and halfword rows omit the acquire-only and release-only forms.
	if !matched || !encoded && size < 2 && (order == 1 || order == 2) {
		return arm64AtomicCASForm{}, false
	}
	return arm64AtomicCASForm{typeName: arm64AtomicWidthType[size], order: order}, true
}

func parseARM64AtomicRMWOpcode(op Op) (arm64AtomicRMWForm, bool) {
	name := strings.ToUpper(string(op))
	for _, spec := range arm64AtomicRMWSpecs {
		if spec.stem == "" || !strings.HasPrefix(name, spec.stem) {
			continue
		}
		size, order, matched := arm64AtomicLSEFormat(name[len(spec.stem):])
		if !matched {
			return arm64AtomicRMWForm{}, false
		}
		return arm64AtomicRMWForm{
			typeName: arm64AtomicWidthType[size], operation: spec.operation, order: order, invert: spec.invert,
		}, true
	}
	return arm64AtomicRMWForm{}, false
}

func decodeARM64LSEScalarWord(word uint32, original Instr) (Instr, bool) {
	const registersAndSize = uint32(3<<30 | 31<<16 | 31<<5 | 31)
	const casFields = registersAndSize | 1<<22 | 1<<15
	const rmwFields = registersAndSize | 3<<22 | 15<<12
	var stem string
	var order uint32
	switch {
	case word&^casFields == 0x08a07c00:
		stem, order = "CAS", (word>>21)&2|(word>>15)&1
	case word&^rmwFields == 0x38200000:
		operation := word >> 12 & 15
		if operation >= uint32(len(arm64AtomicRMWSpecs)) || arm64AtomicRMWSpecs[operation].stem == "" {
			return Instr{}, false
		}
		stem, order = arm64AtomicRMWSpecs[operation].stem, word>>22&3
	default:
		return Instr{}, false
	}
	register := func(n uint32, reg31 Reg) Reg {
		if n == 31 {
			return reg31
		}
		return Reg(fmt.Sprintf("R%d", n))
	}
	return Instr{
		Op: Op(stem + arm64AtomicOrderSuffix[order] + string(arm64AtomicWidthSuffix[word>>30])),
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
	if form, matched := parseARM64AtomicRMWOpcode(op); matched {
		return true, false, c.lowerAtomicRMWFamily(form, ins)
	}
	if form, matched := parseARM64AtomicCASOpcode(op, ins.arm64Encoded); matched {
		return true, false, c.lowerAtomicCASFamily(form, ins)
	}
	if form, matched := parseARM64ExclusiveOpcode(op); matched {
		return true, false, c.lowerExclusiveFamily(form, ins)
	}
	if ty, load, matched := parseARM64AtomicLoadStoreOpcode(op); matched {
		return true, false, c.lowerOrderedAtomicMemory(ins, ty, load)
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

func arm64LSEOutputOrdering(order uint32, output Reg) uint32 {
	// CAS returns the old value in its first operand (Rs), whereas the
	// arithmetic/swap families return it in their final operand (Rt).
	if output == ZR {
		return order &^ arm64AtomicAcquireBit
	}
	return order
}

func (c *arm64Ctx) lowerAtomicRMWFamily(form arm64AtomicRMWForm, ins Instr) error {
	mem, err := arm64ScalarAtomicMemory(ins, 1, 3)
	if err != nil {
		return err
	}
	source64, err := c.loadRegisterWidth(ins.Args[0].Reg, arm64MachineScalarWidth(form.typeName))
	if err != nil {
		return err
	}
	source, err := c.atomicTruncFromI64(source64, form.typeName)
	if err != nil {
		return err
	}
	argument := source
	if form.invert {
		inverted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, -1\n", inverted, form.typeName, source)
		argument = "%" + inverted
	}
	pointer, err := c.atomicMemPtr(mem)
	if err != nil {
		return err
	}
	old := c.newTmp()
	order := arm64LSEOutputOrdering(form.order, ins.Args[2].Reg)
	fmt.Fprintf(c.b, "  %%%s = atomicrmw %s ptr %s, %s %s %s\n",
		old, form.operation, pointer, form.typeName, argument, arm64AtomicOrdering[order])
	old64, err := c.atomicExtendToI64("%"+old, form.typeName)
	if err != nil {
		return err
	}
	return c.storeReg(ins.Args[2].Reg, old64)
}

func (c *arm64Ctx) lowerAtomicCASFamily(form arm64AtomicCASForm, ins Instr) error {
	mem, err := arm64ScalarAtomicMemory(ins, 1, 3)
	if err != nil {
		return err
	}
	width := arm64MachineScalarWidth(form.typeName)
	expected64, err := c.loadRegisterWidth(ins.Args[0].Reg, width)
	if err != nil {
		return err
	}
	expected, err := c.atomicTruncFromI64(expected64, form.typeName)
	if err != nil {
		return err
	}
	new64, err := c.loadRegisterWidth(ins.Args[2].Reg, width)
	if err != nil {
		return err
	}
	newValue, err := c.atomicTruncFromI64(new64, form.typeName)
	if err != nil {
		return err
	}
	pointer, err := c.atomicMemPtr(mem)
	if err != nil {
		return err
	}
	align, err := arm64AtomicTypeSize(form.typeName)
	if err != nil {
		return err
	}
	changed := c.newTmp()
	order := arm64LSEOutputOrdering(form.order, ins.Args[0].Reg)
	fmt.Fprintf(c.b, "  %%%s = cmpxchg ptr %s, %s %s, %s %s %s %s, align %d\n",
		changed, pointer, form.typeName, expected, form.typeName, newValue,
		arm64AtomicOrdering[order], arm64AtomicOrdering[order&arm64AtomicAcquireBit], align)
	old := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractvalue {%s, i1} %%%s, 0\n", old, form.typeName, changed)
	old64, err := c.atomicExtendToI64("%"+old, form.typeName)
	if err != nil {
		return err
	}
	return c.storeReg(ins.Args[0].Reg, old64)
}

func (c *arm64Ctx) lowerExclusiveFamily(form arm64ExclusiveForm, ins Instr) error {
	memoryIndex, wantArgs := 1, 3
	if form.isLoad {
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
	size, err := arm64AtomicTypeSize(form.typeName)
	if err != nil {
		return err
	}
	if form.isLoad {
		loaded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load atomic %s, ptr %s %s, align %d\n", loaded, form.typeName, pointer, form.successOrder, size)
		value64, err := c.atomicExtendToI64("%"+loaded, form.typeName)
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
	newValue, err := c.atomicTruncFromI64(source64, form.typeName)
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
	expected, err := c.atomicTruncFromI64("%"+expected64, form.typeName)
	if err != nil {
		return err
	}
	changed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = cmpxchg ptr %s, %s %s, %s %s %s %s, align %d\n",
		changed, pointer, form.typeName, expected, form.typeName, newValue, form.successOrder, form.failureOrder, size)
	succeeded := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractvalue {%s, i1} %%%s, 1\n", succeeded, form.typeName, changed)
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
