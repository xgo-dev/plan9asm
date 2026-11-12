package plan9asm

import (
	"fmt"
	"sort"
	"strings"
)

// A namespace is a compiler name allocation, never a source certificate.
func x86LockScalarNamespace(file *File, arch string, resolve func(string) string, sigs map[string]FuncSig) string {
	if len(x86LockScalarRMWHelperForms(file, arch)) == 0 {
		return ""
	}
	return x86CompilerHelperNamespace(file, resolve, sigs, "lock_rmw")
}

func x86LockScalarHelperName(namespace string, form x86LockScalarRMWForm, arch string) string {
	segment := "native"
	if form.destination.Kind == OpMem && form.destination.Mem.Segment != "" {
		segment = strings.ToLower(string(form.destination.Mem.Segment))
	}
	name := namespace + arch + "_" + strings.ToLower(form.spec.stem) + fmt.Sprint(form.spec.bits) + "_" + segment
	if form.source.Kind == OpImm {
		name += fmt.Sprintf("_imm_%016x", uint64(form.source.Imm))
	}
	return name
}

func x86LockScalarPointerType(form x86LockScalarRMWForm) string {
	if form.destination.Kind == OpMem {
		switch form.destination.Mem.Segment {
		case FS:
			return "ptr addrspace(257)"
		case GS:
			return "ptr addrspace(256)"
		}
	}
	return "ptr"
}

func x86LockScalarRMWHelperForms(file *File, arch string) map[string]x86LockScalarRMWForm {
	forms := make(map[string]x86LockScalarRMWForm)
	if file == nil || file.Arch != ArchAMD64 || arch != "amd64" && arch != "386" {
		return forms
	}
	for _, fn := range file.Funcs {
		for _, block := range amd64SplitBlocks(fn) {
			for index := 1; index < len(block.instrs); index++ {
				prefix, body := block.instrs[index-1], block.instrs[index]
				if !strings.EqualFold(string(prefix.Op), "LOCK") || len(prefix.Args) != 0 {
					continue
				}
				form, recognized, err := x86LockScalarRMWProperties(body.Op, body, arch)
				if !recognized || err != nil || x86LockScalarNativeMemoryBound(form, body, arch) != nil {
					continue // The ordinary final consumer retains the actual error.
				}
				forms[x86LockScalarHelperName("", form, arch)] = form
			}
		}
	}
	return forms
}

func emitX86LockScalarRMWHelpers(b *strings.Builder, file *File, arch, namespace string) {
	if namespace == "" {
		return
	}
	forms := x86LockScalarRMWHelperForms(file, arch)
	names := make([]string, 0, len(forms))
	for name := range forms {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		emitX86LockScalarRMWHelper(b, namespace+name, forms[name], arch)
	}
}

func emitX86LockScalarRMWHelper(b *strings.Builder, name string, form x86LockScalarRMWForm, arch string) {
	spec := form.spec
	typ, word := amd64IntegerTypeForBits(spec.bits), I64
	push, pop, carryTest := "pushfq", "popq", "btq"
	if arch == "386" {
		word, push, pop, carryTest = I32, "pushfl", "popl", "btl"
	}
	pointer := x86LockScalarPointerType(form)
	fmt.Fprintf(b, "define internal %s @%s(%s %%memory, %s %%source, %s %%carry) noinline noredzone {\nentry:\n",
		word, name, pointer, typ, word)
	width := map[int]string{8: "b", 16: "w", 32: "l", 64: "q"}[spec.bits]
	segment := ""
	if form.destination.Kind == OpMem && form.destination.Mem.Segment != "" {
		segment = "%" + strings.ToLower(string(form.destination.Mem.Segment)) + ":"
	}
	// The only native stack use is balanced within this compiler-owned helper.
	// noinline+noredzone prevents a later inliner/red-zone allocation from
	// invalidating it. No source SP/FP allocation or extra LAHF ISA is borrowed.
	if spec.stem == "NOT" {
		fmt.Fprintf(b, "  call void asm sideeffect \"lock; not%s %s$0\", \"=*m,*m,~{memory},~{dirflag},~{fpsr},~{flags}\"(%s elementtype(%s) %%memory, %s elementtype(%s) %%memory)\n",
			width, segment, pointer, typ, pointer, typ)
		fmt.Fprintf(b, "  ret %s 0\n}\n\n", word)
		return
	}
	opcode := "lock; " + strings.ToLower(spec.stem) + width + " "
	if spec.unary {
		opcode += segment + "$1"
	} else {
		opcode += "$2, " + segment + "$1"
	}
	if spec.carryInput {
		opcode = carryTest + " $$0, $3; " + opcode
	}
	opcode += "; " + push + "; " + pop + " $0"
	register := "r"
	if spec.bits == 8 {
		register = "q"
	}
	source := "%source"
	if form.source.Kind == OpImm {
		register, source = "i", fmt.Sprint(form.source.Imm)
	}
	// Keep fixed operand numbering even for unary forms. The unused source is
	// a compile-time zero, not an invented machine input. Output flags are
	// written after every input is consumed; indirect *m is read/write.
	fmt.Fprintf(b, "  %%flags = call %s asm sideeffect \"%s\", \"=r,=*m,%s,r,*m,~{memory},~{dirflag},~{fpsr},~{flags}\"(%s elementtype(%s) %%memory, %s %s, %s %%carry, %s elementtype(%s) %%memory)\n",
		word, opcode, register, pointer, typ, typ, source, word, pointer, typ)
	fmt.Fprintf(b, "  ret %s %%flags\n}\n\n", word)
}

func (c *amd64Ctx) lowerLockScalarRMW(op Op, ins Instr) (bool, bool, error) {
	if !c.namedAtomicLock {
		return false, false, nil
	}
	form, recognized, err := x86LockScalarRMWProperties(op, ins, c.goarch)
	if !recognized {
		return false, false, nil
	}
	if err != nil {
		return true, false, err
	}
	if err := x86LockScalarNativeMemoryBound(form, ins, c.goarch); err != nil {
		return true, false, err
	}
	if c.lockScalarNS == "" {
		return true, false, fmt.Errorf("%w: scalar LOCK has no compiler-owned complete bridge", ErrProbeNeedsContext)
	}
	pointer, pointerType, err := c.compareExchangePointer(form.destination)
	if err != nil {
		return true, false, err
	}
	if pointerType != x86LockScalarPointerType(form) {
		return true, false, fmt.Errorf("%w: scalar LOCK native address space changed", ErrProbeNeedsContext)
	}
	typ, word := amd64IntegerTypeForBits(form.spec.bits), I64
	if c.goarch == "386" {
		word = I32
	}
	source := "0"
	if !form.spec.unary {
		if form.source.Kind == OpImm {
			source = fmt.Sprint(form.source.Imm)
		} else if source, err = c.evalIntSized(form.source, typ); err != nil {
			return true, false, err
		}
	}
	carry := "0"
	if form.spec.carryInput {
		flag := c.loadFlag(c.flagsCFSlot)
		name := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i1 %s to %s\n", name, flag, word)
		carry = "%" + name
	}
	flags := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @%s(%s %s, %s %s, %s %s)\n", flags, word,
		x86LockScalarHelperName(c.lockScalarNS, form, c.goarch), pointerType, pointer, typ, source, word, carry)
	for _, flag := range []struct {
		mask uint8
		bit  int
		slot string
	}{
		{x86ByteFlagCF, 0, c.flagsCFSlot},
		{x86ByteFlagPF, 2, c.flagsPFSlot},
		{x86ByteFlagAF, 4, c.flagsAFSlot},
		{x86ByteFlagZF, 6, c.flagsZSlot},
		{x86ByteFlagSF, 7, c.flagsSltSlot},
		{x86ByteFlagOF, 11, c.flagsOFSlot},
	} {
		if form.spec.flagsDefined&flag.mask == 0 {
			continue // Preserved/undefined bits are not forged into defined facts.
		}
		shift, value := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr %s %%%s, %d\n", shift, word, flags, flag.bit)
		fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to i1\n", value, word, shift)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", value, flag.slot)
	}
	return true, false, nil
}
