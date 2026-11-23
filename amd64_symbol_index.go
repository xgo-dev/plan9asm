package plan9asm

import (
	"fmt"
	"strings"
)

// Non-shared 386 TYPE_ADDR EXTERN/STATIC is Yi32. The registered scalar-L
// arithmetic and PUSHL rows have a four-byte relocation sink; B/W emitters
// have none, and ordinary amd64 named addresses are Yiauto. This shared source
// class grants neither memory access, native stack nor caller permission.
func x86AbsoluteRelocationSource(operand Operand, goarch string, bits int) bool {
	if goarch != "386" || bits != 32 || operand.Kind != OpSym {
		return false
	}
	source := strings.TrimSpace(operand.Sym)
	if !strings.HasPrefix(source, "$") {
		return false
	}
	source = strings.TrimSpace(strings.TrimPrefix(source, "$"))
	if memory, matched, err := parseX86SymbolIndexedMemory(source); matched {
		if err != nil {
			return false
		}
		source = memory.Sym
	}
	if !strings.HasSuffix(source, "(SB)") {
		return false
	}
	name, _, valid := parseFP(strings.TrimSuffix(source, "(SB)") + "(FP)")
	return valid && name != "" && !(name[0] >= '0' && name[0] <= '9') &&
		strings.IndexAny(name, "*/&|^%=!$:[]") < 0
}

func x86SymbolIndexedControlError(ins Instr) error {
	switch normalizeInstructionOpcode(ins.Op) {
	case "CALL", "JMP", "RET":
		for _, operand := range ins.Args {
			if operand.Kind == OpMem && strings.HasSuffix(operand.Mem.Sym, "(SB)") {
				// Go progedit converts named control TYPE_MEM to TYPE_BRANCH,
				// not an indexed memory read. Parsing does not prove this
				// target's relocation, entry/continuation or callee transport.
				return fmt.Errorf("%w: grouped SB control operand needs its Go branch/entry contract", ErrProbeNeedsContext)
			}
		}
	}
	return nil
}

type x86SourceBranchTarget struct {
	symbol string
	addend int64
}

// Go progedit changes grouped SB operands of CALL/JMP/RET to TYPE_BRANCH.
// CALL retains its relocation addend. JMP and the symbolic RET epilogue
// select the symbol's entry, with or without a register group.
func x86DirectSourceBranch(ins Instr, goarch string) (x86SourceBranchTarget, bool) {
	if ins.x86Encoded || ins.x86SourceRaw != nil ||
		ins.Op != OpCALL && ins.Op != OpJMP && ins.Op != OpRET ||
		len(ins.Args) != 1 {
		return x86SourceBranchTarget{}, false
	}
	operand := ins.Args[0]
	var address string
	switch operand.Kind {
	case OpSym:
		address = strings.TrimSpace(operand.Sym)
		if !strings.HasSuffix(address, "(SB)") || strings.HasPrefix(address, "*") || strings.HasPrefix(address, "$") {
			return x86SourceBranchTarget{}, false
		}
	case OpMem:
		// A grouped leading '*' is TYPE_MEM in cmd/asm. An ungrouped
		// leading '*' remains indirect and was excluded above.
		if !x86GroupedSourceBranchOperand(ins, operand.Mem, goarch) {
			return x86SourceBranchTarget{}, false
		}
		address = operand.Mem.Sym
	default:
		return x86SourceBranchTarget{}, false
	}
	symbol, addend, valid := parseSBRef(address)
	if ins.Op != OpCALL {
		addend = 0
	}
	return x86SourceBranchTarget{symbol: symbol, addend: addend}, valid
}

func x86GroupedSourceBranchOperand(ins Instr, memory MemRef, goarch string) bool {
	if !strings.HasSuffix(memory.Sym, "(SB)") || memory.Off != 0 || memory.OffRaw != "" ||
		memory.IndexExt != "" || memory.Segment != "" || memory.Base == "" && memory.Index == "" {
		return false
	}
	if memory.Base != "" && !x86SymbolGoRegisterName(string(memory.Base)) ||
		memory.Index != "" && !x86SymbolGoRegisterName(string(memory.Index)) ||
		goarch == "386" && x86SymbolGIndex.MatchString(ins.Raw) {
		return false
	}
	if memory.Index == "" && memory.Scale != 0 ||
		memory.Scale != 0 && memory.Scale != 1 && memory.Scale != 2 && memory.Scale != 4 && memory.Scale != 8 {
		return false
	}
	// The encoder can still emit a segment prefix from Index. Keep these
	// forms on their physical-prefix path until that contract is available.
	return !x86IsSegmentRegister(memory.Index) && memory.Index != TLS
}

// Derive the ordinary direct branch before declaration and ABI0 analysis.
// Retain the original operands in the parse result for source inventory.
func normalizeX86DirectSourceBranches(file *File, goarch string) *File {
	if file == nil || file.Arch != ArchAMD64 || goarch != "" && goarch != "386" && goarch != "amd64" {
		return file
	}
	result := file
	for index, fn := range file.Funcs {
		if fn.X86RawText != nil || fn.x86RawReplay != nil {
			continue // Preserve the earlier raw-body or replay snapshot.
		}
		var instructions []Instr
		for ordinal, ins := range fn.Instrs {
			target, ok := x86DirectSourceBranch(ins, goarch)
			if !ok {
				continue
			}
			spelling := target.symbol
			if target.addend != 0 {
				spelling += fmt.Sprintf("%+d", target.addend)
			}
			spelling += "(SB)"
			if ins.Args[0].Kind == OpSym && ins.Args[0].Sym == spelling {
				continue
			}
			if (target.addend != 0 || strings.HasSuffix(target.symbol, "<>")) &&
				!x86SourceBranchOwnsText(file, target.symbol) {
				continue
			}
			if instructions == nil {
				instructions = append([]Instr(nil), fn.Instrs...)
			}
			ins.Args = []Operand{{Kind: OpSym, Sym: spelling}}
			instructions[ordinal] = ins
		}
		if instructions == nil {
			continue
		}
		if result == file {
			derived := *file
			derived.Funcs = append([]Func(nil), file.Funcs...)
			result = &derived
		}
		result.Funcs[index].Instrs = instructions
	}
	return result
}

func x86SourceBranchOwnsText(file *File, symbol string) bool {
	for _, fn := range file.Funcs {
		if fn.Sym == symbol {
			return true
		}
	}
	return false
}

// asm6.oclass requires a named PARAM/AUTO base to be absent or SP and rejects
// ordinary AMD64 EXTERN/STATIC base/index registers (their native base is RIP).
// In 386, asmandsz ignores Reg for these names but still consumes Index.
// This describes native operand shape only, never a memory/ABI permission.
func x86SymbolIndexedMemoryError(memory MemRef, arch string) error {
	if memory.Sym == "" {
		return nil
	}
	if memory.Base == TLS || memory.Index == TLS {
		return fmt.Errorf("%w: named-memory TLS needs its actual Go progedit and native TLS address contract", ErrProbeNeedsContext)
	}
	if arch == "386" && memory.Base != "" && !isX86YrlRegisterForArch(memory.Base, arch) {
		// Except for progedit's TLS rewrite above, Go's named-memory encoder
		// discards Reg, including FS/GS and SIMD annotations. Validate its
		// complete spelling before discarding it, not its physical GP bank.
		if !x86SymbolGoRegisterName(string(memory.Base)) {
			return fmt.Errorf("386 named-memory has an unknown Go Reg annotation")
		}
	}
	validation := memory
	if arch == "386" {
		validation.Base = "" // All named 386 TYPE_MEM roles ignore Reg.
	}
	switch memory.Index {
	case "CS", "SS", "DS", "ES", FS, GS:
		return fmt.Errorf("%w: named-memory segment index needs native segment address provenance", ErrProbeNeedsContext)
	}
	if !x86MemoryRegistersValidForArch(validation, arch) || memory.IndexExt != "" ||
		memory.Index == SP || memory.Index != "" && memory.Scale != 1 && memory.Scale != 2 && memory.Scale != 4 && memory.Scale != 8 {
		return fmt.Errorf("%s symbolic memory has an unencodable base/index/scale", arch)
	}
	symbol := strings.TrimSpace(memory.Sym)
	if strings.HasSuffix(symbol, "(FP)") || strings.HasSuffix(symbol, "(SP)") {
		if arch != "386" && memory.Base != "" && memory.Base != SP {
			return fmt.Errorf("amd64 named FP/AUTO memory must have an absent or SP base")
		}
		return fmt.Errorf("%w: indexed FP/AUTO address needs its original contiguous frame, dynamic extent and address provenance", ErrProbeNeedsContext)
	}
	if !strings.HasSuffix(symbol, "(SB)") {
		return fmt.Errorf("unsupported x86 symbolic memory role: %q", memory.Sym)
	}
	if arch != "386" && (memory.Base != "" || memory.Index != "" || memory.Scale != 0) {
		return fmt.Errorf("amd64 Go SB memory cannot combine RIP with a base/index register")
	}
	return nil
}

func (c *amd64Ctx) addrFromSymbolIndexedAddress(memory MemRef) (string, error) {
	if c.goarch == "386" && strings.HasSuffix(memory.Sym, "(SB)") {
		// TYPE_ADDR is Yi32 in non-shared 386, not Yiauto. The source
		// registers are annotations on a relocated immediate, not inputs to
		// an effective-address calculation (unlike TYPE_MEM/LEA).
		for _, register := range []Reg{memory.Base, memory.Index} {
			if register != "" && !x86SymbolGoRegisterName(string(register)) {
				return "", fmt.Errorf("386 symbolic address has an unknown Go register annotation")
			}
		}
		if memory.IndexExt != "" {
			return "", fmt.Errorf("386 symbolic address has an unknown register extension")
		}
		switch memory.Index {
		case "CS", "DS", "ES", FS, GS:
			return "", fmt.Errorf("%w: relocated immediate segment Index needs its source-encoder prefix contract", ErrProbeNeedsContext)
		}
		memory.Base, memory.Index, memory.IndexExt, memory.Scale = "", "", "", 0
	}
	return c.addrFromMem(memory)
}
