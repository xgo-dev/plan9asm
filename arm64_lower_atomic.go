package plan9asm

import (
	"fmt"
	"strings"
)

type arm64AtomicRMWForm struct {
	typeName  LLVMType
	operation string
	ordering  string
	invert    bool
}

type arm64AtomicCASForm struct {
	typeName     LLVMType
	successOrder string
	failureOrder string
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
	switch strings.TrimPrefix(name, prefix) {
	case "":
		form.typeName = I64
	case "B":
		form.typeName = I8
	case "H":
		form.typeName = I16
	case "W":
		form.typeName = I32
	default:
		return arm64ExclusiveForm{}, false
	}
	return form, true
}

func parseARM64AtomicCASOpcode(op Op) (arm64AtomicCASForm, bool) {
	name := strings.ToUpper(string(op))
	if !strings.HasPrefix(name, "CAS") || strings.HasPrefix(name, "CASP") || len(name) < 4 {
		return arm64AtomicCASForm{}, false
	}
	tail := strings.TrimPrefix(name, "CAS")
	typeName := LLVMType("")
	width := tail[len(tail)-1]
	switch width {
	case 'B':
		typeName = I8
	case 'H':
		typeName = I16
	case 'W':
		typeName = I32
	case 'D':
		typeName = I64
	default:
		return arm64AtomicCASForm{}, false
	}
	order := tail[:len(tail)-1]
	form := arm64AtomicCASForm{typeName: typeName}
	switch order {
	case "":
		form.successOrder, form.failureOrder = "monotonic", "monotonic"
	case "A":
		if width == 'B' || width == 'H' {
			return arm64AtomicCASForm{}, false
		}
		form.successOrder, form.failureOrder = "acquire", "acquire"
	case "L":
		if width == 'B' || width == 'H' {
			return arm64AtomicCASForm{}, false
		}
		form.successOrder, form.failureOrder = "release", "monotonic"
	case "AL":
		form.successOrder, form.failureOrder = "acq_rel", "acquire"
	default:
		return arm64AtomicCASForm{}, false
	}
	return form, true
}

func parseARM64AtomicRMWOpcode(op Op) (arm64AtomicRMWForm, bool) {
	name := strings.ToUpper(string(op))
	operation := ""
	invert := false
	prefix := ""
	for _, candidate := range []struct {
		prefix    string
		operation string
		invert    bool
	}{
		{"LDADD", "add", false},
		{"LDCLR", "and", true},
		{"LDEOR", "xor", false},
		{"LDOR", "or", false},
		{"SWP", "xchg", false},
	} {
		if strings.HasPrefix(name, candidate.prefix) {
			prefix, operation, invert = candidate.prefix, candidate.operation, candidate.invert
			break
		}
	}
	if prefix == "" {
		return arm64AtomicRMWForm{}, false
	}
	tail := strings.TrimPrefix(name, prefix)
	if len(tail) < 1 {
		return arm64AtomicRMWForm{}, false
	}
	typeName := LLVMType("")
	switch tail[len(tail)-1] {
	case 'B':
		typeName = I8
	case 'H':
		typeName = I16
	case 'W':
		typeName = I32
	case 'D':
		typeName = I64
	default:
		return arm64AtomicRMWForm{}, false
	}
	ordering := ""
	switch tail[:len(tail)-1] {
	case "":
		ordering = "monotonic"
	case "A":
		ordering = "acquire"
	case "L":
		ordering = "release"
	case "AL":
		ordering = "acq_rel"
	default:
		return arm64AtomicRMWForm{}, false
	}
	return arm64AtomicRMWForm{typeName: typeName, operation: operation, ordering: ordering, invert: invert}, true
}

func (c *arm64Ctx) lowerAtomic(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if ok, terminated, err := c.lowerAtomicPair(op, ins); ok {
		return ok, terminated, err
	}
	if form, matched := parseARM64AtomicRMWOpcode(op); matched {
		return true, false, c.lowerAtomicRMWFamily(form, ins)
	}
	if form, matched := parseARM64AtomicCASOpcode(op); matched {
		return true, false, c.lowerAtomicCASFamily(form, ins)
	}
	if form, matched := parseARM64ExclusiveOpcode(op); matched {
		return true, false, c.lowerExclusiveFamily(form, ins)
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

	case "LDARW", "LDARH", "LDARB", "LDAR", "LDAXRW", "LDAXRB", "LDAXR":
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpMem || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 %s expects mem, reg: %q", op, ins.Raw)
		}
		if !arm64AtomicZeroOffsetMemory(ins.Args[0].Mem) {
			return true, false, fmt.Errorf("arm64 %s memory must be a zero-offset general-register, RSP, or ZR address: %q", op, ins.Raw)
		}
		ty, align := arm64AtomicLoadStoreType(op)
		ptr, err := c.atomicMemPtr(ins.Args[0].Mem)
		if err != nil {
			return true, false, err
		}
		ld := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load atomic %s, ptr %s acquire, align %d\n", ld, ty, ptr, align)
		v, err := c.atomicExtendToI64("%"+ld, ty)
		if err != nil {
			return true, false, err
		}
		if op == "LDAXRW" || op == "LDAXRB" || op == "LDAXR" {
			size, err := arm64AtomicTypeSize(ty)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  store i1 true, ptr %s\n", c.exclusiveValidSlot)
			fmt.Fprintf(c.b, "  store ptr %s, ptr %s\n", ptr, c.exclusivePtrSlot)
			fmt.Fprintf(c.b, "  store i8 %d, ptr %s\n", size, c.exclusiveSizeSlot)
			fmt.Fprintf(c.b, "  store i64 %s, ptr %s\n", v, c.exclusiveValueSlot)
		}
		return true, false, c.storeReg(ins.Args[1].Reg, v)

	case "STLRW", "STLRH", "STLRB", "STLR":
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpMem {
			return true, false, fmt.Errorf("arm64 %s expects reg, mem: %q", op, ins.Raw)
		}
		if !arm64AtomicZeroOffsetMemory(ins.Args[1].Mem) {
			return true, false, fmt.Errorf("arm64 %s memory must be a zero-offset general-register, RSP, or ZR address: %q", op, ins.Raw)
		}
		ty, align := arm64AtomicLoadStoreType(op)
		src, err := c.loadReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		v, err := c.atomicTruncFromI64(src, ty)
		if err != nil {
			return true, false, err
		}
		ptr, err := c.atomicMemPtr(ins.Args[1].Mem)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  store atomic %s %s, ptr %s release, align %d\n", ty, v, ptr, align)
		return true, false, nil

	case "STLXRW", "STLXRB", "STLXR":
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpMem || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 %s expects srcReg, mem, statusReg: %q", op, ins.Raw)
		}
		ty, align := arm64AtomicStoreExclusiveType(op)
		size, err := arm64AtomicTypeSize(ty)
		if err != nil {
			return true, false, err
		}
		src, err := c.loadReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		newv, err := c.atomicTruncFromI64(src, ty)
		if err != nil {
			return true, false, err
		}
		ptr, err := c.atomicMemPtr(ins.Args[1].Mem)
		if err != nil {
			return true, false, err
		}

		loadedValid := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", loadedValid, c.exclusiveValidSlot)
		loadedPtr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load ptr, ptr %s\n", loadedPtr, c.exclusivePtrSlot)
		ptrMatch := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq ptr %%%s, %s\n", ptrMatch, loadedPtr, ptr)
		loadedSize := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i8, ptr %s\n", loadedSize, c.exclusiveSizeSlot)
		sizeMatch := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i8 %%%s, %d\n", sizeMatch, loadedSize, size)
		precond := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", precond, loadedValid, ptrMatch)
		canTry := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", canTry, precond, sizeMatch)

		id := c.newTmp()
		tryLabel := arm64LLVMBlockName("stlxr_try_" + id)
		failLabel := arm64LLVMBlockName("stlxr_fail_" + id)
		mergeLabel := arm64LLVMBlockName("stlxr_merge_" + id)

		fmt.Fprintf(c.b, "  br i1 %%%s, label %%%s, label %%%s\n", canTry, tryLabel, failLabel)

		fmt.Fprintf(c.b, "\n%s:\n", tryLabel)
		expected64 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s\n", expected64, c.exclusiveValueSlot)
		expected, err := c.atomicTruncFromI64("%"+expected64, ty)
		if err != nil {
			return true, false, err
		}
		cx := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = cmpxchg ptr %s, %s %s, %s %s seq_cst seq_cst, align %d\n", cx, ptr, ty, expected, ty, newv, align)
		ok := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue {%s, i1} %%%s, 1\n", ok, ty, cx)
		failI1 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", failI1, ok)
		tryStatus := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i1 %%%s to i64\n", tryStatus, failI1)
		fmt.Fprintf(c.b, "  br label %%%s\n", mergeLabel)

		fmt.Fprintf(c.b, "\n%s:\n", failLabel)
		fmt.Fprintf(c.b, "  br label %%%s\n", mergeLabel)

		fmt.Fprintf(c.b, "\n%s:\n", mergeLabel)
		status := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = phi i64 [ %%%s, %%%s ], [ 1, %%%s ]\n", status, tryStatus, tryLabel, failLabel)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.exclusiveValidSlot)
		return true, false, c.storeReg(ins.Args[2].Reg, "%"+status)

	case "SWPALB", "SWPALW", "SWPALD":
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpMem || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 %s expects srcReg, mem, dstReg: %q", op, ins.Raw)
		}
		ty, err := arm64AtomicRMWType(op)
		if err != nil {
			return true, false, err
		}
		src64, err := c.loadReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		src, err := c.atomicTruncFromI64(src64, ty)
		if err != nil {
			return true, false, err
		}
		ptr, err := c.atomicMemPtr(ins.Args[1].Mem)
		if err != nil {
			return true, false, err
		}
		old := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = atomicrmw xchg ptr %s, %s %s seq_cst\n", old, ptr, ty, src)
		old64, err := c.atomicExtendToI64("%"+old, ty)
		if err != nil {
			return true, false, err
		}
		return true, false, c.storeReg(ins.Args[2].Reg, old64)

	case "LDADDALW", "LDADDALD", "LDORALB", "LDORALW", "LDORALD", "LDCLRALB", "LDCLRALW", "LDCLRALD",
		"LDEORB", "LDEORH", "LDEORW", "LDEORD",
		"LDEORAB", "LDEORAH", "LDEORAW", "LDEORAD",
		"LDEORLB", "LDEORLH", "LDEORLW", "LDEORLD",
		"LDEORALB", "LDEORALH", "LDEORALW", "LDEORALD":
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpMem || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 %s expects srcReg, mem, dstReg: %q", op, ins.Raw)
		}
		ty, err := arm64AtomicRMWType(op)
		if err != nil {
			return true, false, err
		}
		src64, err := c.loadReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		src, err := c.atomicTruncFromI64(src64, ty)
		if err != nil {
			return true, false, err
		}
		ptr, err := c.atomicMemPtr(ins.Args[1].Mem)
		if err != nil {
			return true, false, err
		}

		rmwo := ""
		arg := src
		switch op {
		case "LDADDALW", "LDADDALD":
			rmwo = "add"
		case "LDORALB", "LDORALW", "LDORALD":
			rmwo = "or"
		case "LDEORB", "LDEORH", "LDEORW", "LDEORD",
			"LDEORAB", "LDEORAH", "LDEORAW", "LDEORAD",
			"LDEORLB", "LDEORLH", "LDEORLW", "LDEORLD",
			"LDEORALB", "LDEORALH", "LDEORALW", "LDEORALD":
			rmwo = "xor"
		case "LDCLRALB", "LDCLRALW", "LDCLRALD":
			rmwo = "and"
			// LDCLR updates memory as: mem = mem & ~src.
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor %s %s, -1\n", t, ty, src)
			arg = "%" + t
		}

		old := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = atomicrmw %s ptr %s, %s %s seq_cst\n", old, rmwo, ptr, ty, arg)
		old64, err := c.atomicExtendToI64("%"+old, ty)
		if err != nil {
			return true, false, err
		}
		return true, false, c.storeReg(ins.Args[2].Reg, old64)

	case "CASALW", "CASALD":
		// CASAL{W,D} expectedReg, (ptrReg), newReg
		// The expected register is updated with the loaded memory value.
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpMem || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 %s expects expectedReg, mem, newReg: %q", op, ins.Raw)
		}
		ty := I32
		align := 4
		if op == "CASALD" {
			ty = I64
			align = 8
		}
		exp64, err := c.loadReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		exp, err := c.atomicTruncFromI64(exp64, ty)
		if err != nil {
			return true, false, err
		}
		new64, err := c.loadReg(ins.Args[2].Reg)
		if err != nil {
			return true, false, err
		}
		newv, err := c.atomicTruncFromI64(new64, ty)
		if err != nil {
			return true, false, err
		}
		ptr, err := c.atomicMemPtr(ins.Args[1].Mem)
		if err != nil {
			return true, false, err
		}
		cx := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = cmpxchg ptr %s, %s %s, %s %s seq_cst seq_cst, align %d\n", cx, ptr, ty, exp, ty, newv, align)
		old := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue {%s, i1} %%%s, 0\n", old, ty, cx)
		old64, err := c.atomicExtendToI64("%"+old, ty)
		if err != nil {
			return true, false, err
		}
		return true, false, c.storeReg(ins.Args[0].Reg, old64)
	}
	return false, false, nil
}

func (c *arm64Ctx) lowerAtomicRMWFamily(form arm64AtomicRMWForm, ins Instr) error {
	if arm64AtomicOpcodeHasSuffix(ins.Op) || len(ins.Args) != 3 ||
		ins.Args[0].Kind != OpReg || !isARM64GeneralOrZeroReg(ins.Args[0].Reg) ||
		ins.Args[1].Kind != OpMem ||
		ins.Args[2].Kind != OpReg || !isARM64GeneralOrZeroReg(ins.Args[2].Reg) {
		return fmt.Errorf("arm64 %s expects source register, zero-offset register memory, destination register: %q", ins.Op, ins.Raw)
	}
	mem := ins.Args[1].Mem
	if mem.Sym != "" || mem.Segment != "" || mem.Index != "" || mem.Off != 0 || mem.OffRaw != "" ||
		(mem.Base != Reg("RSP") && !isARM64GeneralOrZeroReg(mem.Base)) {
		return fmt.Errorf("arm64 %s memory must be exactly (R0-R30), (RSP), or (ZR): %q", ins.Op, ins.Raw)
	}
	source64, err := c.loadReg(ins.Args[0].Reg)
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
	fmt.Fprintf(c.b, "  %%%s = atomicrmw %s ptr %s, %s %s %s\n", old, form.operation, pointer, form.typeName, argument, form.ordering)
	old64, err := c.atomicExtendToI64("%"+old, form.typeName)
	if err != nil {
		return err
	}
	return c.storeReg(ins.Args[2].Reg, old64)
}

func (c *arm64Ctx) lowerAtomicCASFamily(form arm64AtomicCASForm, ins Instr) error {
	if arm64AtomicOpcodeHasSuffix(ins.Op) || len(ins.Args) != 3 ||
		ins.Args[0].Kind != OpReg || !isARM64GeneralOrZeroReg(ins.Args[0].Reg) ||
		ins.Args[1].Kind != OpMem ||
		ins.Args[2].Kind != OpReg || !isARM64GeneralOrZeroReg(ins.Args[2].Reg) {
		return fmt.Errorf("arm64 %s expects expected register, zero-offset register memory, new-value register: %q", ins.Op, ins.Raw)
	}
	mem := ins.Args[1].Mem
	if mem.Sym != "" || mem.Segment != "" || mem.Index != "" || mem.Off != 0 || mem.OffRaw != "" ||
		(mem.Base != Reg("RSP") && !isARM64GeneralOrZeroReg(mem.Base)) {
		return fmt.Errorf("arm64 %s memory must be exactly (R0-R30), (RSP), or (ZR): %q", ins.Op, ins.Raw)
	}
	expected64, err := c.loadReg(ins.Args[0].Reg)
	if err != nil {
		return err
	}
	expected, err := c.atomicTruncFromI64(expected64, form.typeName)
	if err != nil {
		return err
	}
	new64, err := c.loadReg(ins.Args[2].Reg)
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
	fmt.Fprintf(c.b, "  %%%s = cmpxchg ptr %s, %s %s, %s %s %s %s, align %d\n",
		changed, pointer, form.typeName, expected, form.typeName, newValue, form.successOrder, form.failureOrder, align)
	old := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractvalue {%s, i1} %%%s, 0\n", old, form.typeName, changed)
	old64, err := c.atomicExtendToI64("%"+old, form.typeName)
	if err != nil {
		return err
	}
	return c.storeReg(ins.Args[0].Reg, old64)
}

func (c *arm64Ctx) lowerExclusiveFamily(form arm64ExclusiveForm, ins Instr) error {
	wantArgs := 3
	if form.isLoad {
		wantArgs = 2
	}
	if arm64AtomicOpcodeHasSuffix(ins.Op) || len(ins.Args) != wantArgs {
		return fmt.Errorf("arm64 %s has invalid exclusive load/store operands: %q", ins.Op, ins.Raw)
	}
	memoryIndex := 1
	if form.isLoad {
		memoryIndex = 0
	}
	if ins.Args[memoryIndex].Kind != OpMem {
		return fmt.Errorf("arm64 %s requires a zero-offset register memory operand: %q", ins.Op, ins.Raw)
	}
	mem := ins.Args[memoryIndex].Mem
	if mem.Sym != "" || mem.Segment != "" || mem.Index != "" || mem.Off != 0 || mem.OffRaw != "" ||
		(mem.Base != Reg("RSP") && !isARM64GeneralOrZeroReg(mem.Base)) {
		return fmt.Errorf("arm64 %s memory must be exactly (R0-R30), (RSP), or (ZR): %q", ins.Op, ins.Raw)
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
		if ins.Args[1].Kind != OpReg || !isARM64GeneralOrZeroReg(ins.Args[1].Reg) {
			return fmt.Errorf("arm64 %s destination must be a general register or ZR: %q", ins.Op, ins.Raw)
		}
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
	if ins.Args[0].Kind != OpReg || !isARM64GeneralOrZeroReg(ins.Args[0].Reg) ||
		ins.Args[2].Kind != OpReg || !isARM64GeneralOrZeroReg(ins.Args[2].Reg) {
		return fmt.Errorf("arm64 %s source and status must be general registers or ZR: %q", ins.Op, ins.Raw)
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

func arm64AtomicZeroOffsetMemory(mem MemRef) bool {
	return mem.Sym == "" && mem.Segment == "" && mem.Index == "" && mem.Off == 0 && mem.OffRaw == "" &&
		(mem.Base == Reg("RSP") || isARM64GeneralOrZeroReg(mem.Base))
}

func arm64AtomicLoadStoreType(op Op) (LLVMType, int) {
	switch op {
	case "LDARB", "STLRB":
		return I8, 1
	case "LDARH", "STLRH":
		return I16, 2
	case "LDARW", "LDAXRW", "STLRW":
		return I32, 4
	default:
		return I64, 8
	}
}

func arm64AtomicStoreExclusiveType(op Op) (LLVMType, int) {
	switch op {
	case "STLXRB":
		return I8, 1
	case "STLXRW":
		return I32, 4
	default:
		return I64, 8
	}
}

func arm64AtomicRMWType(op Op) (LLVMType, error) {
	if form, ok := parseARM64AtomicRMWOpcode(op); ok {
		return form.typeName, nil
	}
	switch op {
	case "SWPALB", "LDORALB", "LDCLRALB",
		"LDEORB", "LDEORAB", "LDEORLB", "LDEORALB":
		return I8, nil
	case "LDEORH", "LDEORAH", "LDEORLH", "LDEORALH":
		return I16, nil
	case "SWPALW", "LDADDALW", "LDORALW", "LDCLRALW",
		"LDEORW", "LDEORAW", "LDEORLW", "LDEORALW":
		return I32, nil
	case "SWPALD", "LDADDALD", "LDORALD", "LDCLRALD",
		"LDEORD", "LDEORAD", "LDEORLD", "LDEORALD":
		return I64, nil
	default:
		return "", fmt.Errorf("arm64: unsupported atomic rmw op %s", op)
	}
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
