package plan9asm

import (
	"fmt"
	"strings"
)

type amd64ExchangeKind uint8

const (
	amd64ExchangeSwap amd64ExchangeKind = iota
	amd64ExchangeAdd
)

type amd64ExchangeSpec struct {
	kind amd64ExchangeKind
	bits int
}

// The complete Go yrb_mb/yrl_ml (XADD) and yml_mb/yxchg (XCHG) families.
// Width selects register classes; kind selects operand symmetry and flags.
var amd64ExchangeSpecs = map[Op]amd64ExchangeSpec{
	"XADDB": {amd64ExchangeAdd, 8},
	"XADDW": {amd64ExchangeAdd, 16},
	"XADDL": {amd64ExchangeAdd, 32},
	"XADDQ": {amd64ExchangeAdd, 64},
	"XCHGB": {amd64ExchangeSwap, 8},
	"XCHGW": {amd64ExchangeSwap, 16},
	"XCHGL": {amd64ExchangeSwap, 32},
	"XCHGQ": {amd64ExchangeSwap, 64},
}

type amd64ExchangeForm struct {
	register Operand
	other    Operand
	nop      bool
}

// The swap consumers use the same complete Go grammar as the emitter. Width
// and operand symmetry come from the existing exchange family, not a second
// opcode directory in each provenance or byte observer.
func x86SwapProperties(ins Instr, arch string) (amd64ExchangeForm, int64, bool, error) {
	name := strings.ToUpper(string(ins.Op))
	base, _, _ := strings.Cut(name, ".")
	spec, known := amd64ExchangeSpecs[Op(base)]
	if !known || spec.kind != amd64ExchangeSwap {
		return amd64ExchangeForm{}, 0, false, nil
	}
	form, err := parseAMD64ExchangeForm(arch, Op(name), spec, ins)
	return form, int64(spec.bits / 8), true, err
}

func parseAMD64ExchangeForm(goarch string, op Op, spec amd64ExchangeSpec, ins Instr) (amd64ExchangeForm, error) {
	invalid := func(reason string) (amd64ExchangeForm, error) {
		return amd64ExchangeForm{}, fmt.Errorf("%s %s %s: %q", goarch, op, reason, ins.Raw)
	}
	if strings.Contains(string(op), ".") {
		return invalid("does not accept instruction suffixes")
	}
	if registered, ok := amd64ExchangeSpecs[op]; !ok || registered != spec ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return invalid("does not have its registered source identity and width")
	}
	if goarch != "amd64" && goarch != "386" {
		return invalid("requires a registered x86 mode")
	}
	if goarch == "386" && spec.bits == 64 {
		return invalid("is illegal in 32-bit mode")
	}
	if len(ins.Args) != 2 {
		return invalid("expects two operands")
	}
	first, second := ins.Args[0], ins.Args[1]
	if spec.kind == amd64ExchangeSwap && isAMD64MemoryOperand(first) {
		first, second = second, first
	}
	if projected, segment, err := x86NamedSegmentMemorySource(ins, second, goarch); segment {
		if err != nil {
			return amd64ExchangeForm{}, err
		}
		second = projected
	}
	registerAllowed := func(reg Reg) bool {
		if spec.bits == 8 {
			return isGoYmbRegisterForArch(reg, goarch)
		}
		return isX86YrlRegisterForArch(reg, goarch)
	}
	if first.Kind != OpReg || !registerAllowed(first.Reg) {
		return invalid("requires a source in Go's byte/general-register class")
	}
	if second.Kind == OpReg {
		if !registerAllowed(second.Reg) {
			return invalid("destination is outside Go's byte/general-register class")
		}
	} else if !isAMD64MemoryOperand(second) {
		return invalid("expects a register or memory destination")
	} else if second.Kind == OpMem && !x86MemoryRegistersValidForArch(second.Mem, goarch) {
		return invalid("uses an out-of-range address register")
	}
	form := amd64ExchangeForm{register: first, other: second}
	if goarch == "amd64" && spec.bits == 8 && x86CompareExchangeHasREXByteView(x86CompareExchangeForm{
		source: first, destination: second,
	}) {
		for _, operand := range []Operand{first, second} {
			if operand.Kind == OpReg && (operand.Reg == AH || operand.Reg == CH || operand.Reg == DH || operand.Reg == BH) {
				return amd64ExchangeForm{}, fmt.Errorf("%w: %s %s Go's REX encoding changes a high-byte spelling to an unbound low-byte physical view: %q", ErrProbeNeedsContext, goarch, op, ins.Raw)
			}
		}
	}
	if spec.kind == amd64ExchangeSwap {
		// Go's accumulator/accumulator W/L/Q rows emit opcode 90 (with
		// their width prefix), a NOP. In particular, EAX/EAX does not clear
		// the upper RAX bytes as a genuine ModRM r32 exchange would.
		form.nop = spec.bits != 8 && first.Kind == OpReg && second.Kind == OpReg && first.Reg == AX && second.Reg == AX
	}
	return form, nil
}

func (c *amd64Ctx) lowerExchange(op Op, spec amd64ExchangeSpec, ins Instr) (bool, bool, error) {
	form, err := parseAMD64ExchangeForm(c.goarch, op, spec, ins)
	if err != nil {
		return true, false, err
	}
	if form.nop {
		return true, false, nil
	}
	typ := amd64IntegerTypeForBits(spec.bits)
	value, err := c.evalIntSized(form.register, typ)
	if err != nil {
		return true, false, err
	}
	var old string
	if form.other.Kind == OpReg {
		old, err = c.evalIntSized(form.other, typ)
	} else {
		old, err = c.emitExchangeMemory(spec, form.other, value)
	}
	if err != nil {
		return true, false, err
	}
	result := value
	if spec.kind == amd64ExchangeAdd {
		sum := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", sum, typ, old, value)
		result = "%" + sum
	}
	// Read both operands before writeback. Source-first order preserves identical
	// register XADD and overlapping AH/AL exchanges, including partial writes.
	if err := c.storeRegSized(form.register.Reg, typ, old); err != nil {
		return true, false, err
	}
	if form.other.Kind == OpReg {
		if err := c.storeRegSized(form.other.Reg, typ, result); err != nil {
			return true, false, err
		}
	}
	if spec.kind == amd64ExchangeAdd {
		c.setScalarAddSubFlags(typ, true, old, value, result)
	}
	return true, false, nil
}

func (c *amd64Ctx) emitExchangeMemory(spec amd64ExchangeSpec, memory Operand, value string) (string, error) {
	ptr, ptrType, err := c.compareExchangePointer(memory)
	if err != nil {
		return "", err
	}
	typ := amd64IntegerTypeForBits(spec.bits)
	width := map[int]string{8: "b", 16: "w", 32: "l", 64: "q"}[spec.bits]
	mnemonic := "xchg" + width // A memory XCHG is implicitly locked.
	if spec.kind == amd64ExchangeAdd {
		mnemonic = "xadd" + width
		if c.namedAtomicLock {
			mnemonic = "lock; " + mnemonic
		}
	}
	registerClass := "r"
	if spec.bits == 8 {
		registerClass = "q"
	}
	segment := ""
	if memory.Kind == OpMem && memory.Mem.Segment != "" {
		// LLVM's inline-asm memory operand does not print the address space's
		// FS/GS override; preserve it explicitly in the instruction template.
		segment = "%" + strings.ToLower(string(memory.Mem.Segment)) + ":"
	}
	// Native x86 exchanges support unaligned memory. LLVM atomicrmw align 1
	// can introduce libatomic calls, while claiming natural alignment is false.
	// Explicit read/write memory constraints and the tied register model the
	// native operation without imposing an alignment precondition. Keep memory
	// clobbering for synchronization and preserve segment-relative pointer types.
	old := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect \"%s $0, %s$1\", \"=%s,=*m,0,*m,~{memory},~{dirflag},~{fpsr},~{flags}\"(%s elementtype(%s) %s, %s %s, %s elementtype(%s) %s)\n",
		old, typ, mnemonic, segment, registerClass, ptrType, typ, ptr, typ, value, ptrType, typ, ptr)
	return "%" + old, nil
}
