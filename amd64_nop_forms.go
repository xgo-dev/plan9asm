package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

// Go NOP has a zero-byte pseudo table, whereas NOPW and NOPL encode a real
// ModRM address. Both have empty numerical effects after their own grammar
// succeeds. A completed raw decoder handoff also has an empty effect.
func x86NOPProperties(ins Instr, arch string) (bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	if name != "NOP" && name != "NOPW" && name != "NOPL" {
		return false, nil
	}
	fail := func() (bool, error) {
		return true, fmt.Errorf("%s %s outside the Go NOP operand grammar: %q", arch, ins.Op, ins.Raw)
	}
	if arch != "386" && arch != "amd64" || dotted {
		return fail()
	}
	if name == "NOP" && len(ins.Args) == 0 &&
		(x86ResultNamedPredicateInstruction(ins) || x86NOPPreservesSourceState(ins)) {
		return true, nil
	}
	if len(ins.Args) != 1 {
		return fail()
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		return true, fmt.Errorf("%w: NOP requires named source or the exact inert raw handoff", ErrProbeNeedsContext)
	}
	operand := ins.Args[0]
	if name == "NOP" {
		if arch == "386" && strings.Contains(ins.Raw, "g") {
			raw := strings.TrimSpace(ins.Raw)
			if space := strings.IndexAny(raw, " \t"); space >= 0 {
				literal := strings.TrimSpace(raw[space:])
				if normalizeGoGRegister(ArchAMD64, literal) != literal {
					return fail()
				}
			}
		}
		valid, err := x86PlainNOPOperand(operand, arch)
		if !valid {
			return fail()
		}
		return true, err
	}
	if operand.Kind == OpReg {
		if !isX86YrlRegisterForArch(operand.Reg, arch) {
			return fail()
		}
	} else if !isAMD64MemoryOperand(operand) || !x86PackedShiftMemoryValid(operand, arch) ||
		x86NamedMultiplyMemoryError(operand, arch) != nil {
		return fail()
	}
	return true, nil
}

func x86InertNOP(ins Instr, arch string) bool {
	switch ins.Op {
	case "NOP", "NOPW", "NOPL":
		_, err := x86NOPProperties(ins, arch)
		return err == nil
	default:
		return false
	}
}

func x86PlainNOPOperand(operand Operand, arch string) (bool, error) {
	switch operand.Kind {
	case OpReg:
		return x86PlainNOPRegister(operand.Reg, arch), nil
	case OpIdent:
		return x86PlainNOPRegister(Reg(operand.Ident), arch), nil
	case OpFP, OpFPAddr:
		return operand.FPName != "", nil
	case OpMem:
		return x86PlainNOPMemory(operand.Mem, arch)
	case OpSym:
		text := strings.TrimSpace(operand.Sym)
		body, address := strings.CutPrefix(text, "$")
		body = strings.TrimSpace(body)
		if address {
			// Yiauto covers named stack addresses, and static addresses
			// when the Go assembler uses pc-relative addressing.
			if strings.HasSuffix(body, "(SP)") {
				name, _, valid := parseFP(strings.TrimSuffix(body, "(SP)") + "(FP)")
				_, constant := parseImmExpr(name)
				return valid && !constant, nil
			}
			if memory, matched, err := parseX86SymbolIndexedMemory(body); matched {
				if err != nil {
					return true, err
				}
				return !strings.HasSuffix(memory.Sym, "(SB)") || arch == "amd64", nil
			}
			return arch == "amd64" && x86NOPNamedSymbol(body), nil
		}
		if x86NOPNamedSymbol(body) {
			return true, nil
		}
		if _, absolute := parseImmExpr(body); absolute {
			return true, nil
		}
		// Other consumers represent FS/GS directly. Preserve CS/DS/ES
		// here as well when the common parser left a symbolic operand.
		if memory, matched, err := parseX86SourceRegisterMemory(body); matched && err == nil {
			return x86PlainNOPMemory(memory, arch)
		}
	}
	return false, nil
}

func x86NOPNamedSymbol(text string) bool {
	body, named := strings.CutSuffix(text, "(SB)")
	if !named {
		return false
	}
	name, _, valid := parseFP(body + "(FP)")
	if !valid || strings.IndexAny(name, "*/&|^%=!$:[]") >= 0 {
		return false
	}
	return name[0] < '0' || name[0] > '9'
}

func x86PlainNOPRegister(register Reg, arch string) bool {
	// These are the Yml, Yrf and Yxr register classes. The pseudo
	// table's zero-filled row also accepts an oclass result of Yxxx,
	// including some registers that have no encoding in 386 mode.
	if isAMD64YrlRegister(register) || isX87RegisterOperand(Operand{Kind: OpReg, Reg: register}) {
		return true
	}
	if number, ok := amd64ParseXReg(register); ok {
		return number < 16
	}
	switch register {
	case "SPB", "MAXREG":
		return true // Neither name has a register class in Go's oclass.
	case BPB, SIB, DIB, R8B, R9B, R10B, R11B, R12B, R13B, R14B, R15B:
		return arch == "386"
	}
	if suffix, ok := strings.CutPrefix(string(register), "CR"); ok {
		number, err := strconv.Atoi(suffix)
		return err == nil && number >= 9 && number <= 15
	}
	number, ok := amd64ParseZReg(register)
	return arch == "386" && ok && number >= 8
}

func x86PlainNOPMemory(memory MemRef, arch string) (bool, error) {
	if x86AbsoluteMemoryRef(memory) {
		return true, nil
	}
	if memory.IndexExt != "" || memory.Sym == "" && memory.Base == "" &&
		memory.Index == "" && memory.Segment == "" {
		return false, nil
	}
	if memory.Base != "" && !x86SymbolGoRegisterName(string(memory.Base)) {
		return false, nil
	}
	if memory.Index != "" {
		if !x86SymbolGoRegisterName(string(memory.Index)) ||
			memory.Scale != 0 && memory.Scale != 1 && memory.Scale != 2 && memory.Scale != 4 && memory.Scale != 8 {
			return false, nil
		}
		bytes := amd64VectorByteWidth(memory.Index)
		if index, vector := amd64VectorRegisterIndex(memory.Index, bytes); vector && (arch == "amd64" || index < 8) {
			return false, nil // Go's VSIB classes do not match the pseudo row.
		}
	}
	// Go's prefixof runs before Zpseudo and can leave a byte for the
	// following instruction. This requires that instruction's native
	// encoding and address contract independently of the ignored operand.
	if memory.Segment != "" || x86PlainNOPPrefixRegister(memory.Index) ||
		memory.Sym == "" && x86PlainNOPPrefixRegister(memory.Base) {
		return true, fmt.Errorf("%w: NOP segment/TLS prefix needs the following instruction's native context", ErrProbeNeedsContext)
	}
	return true, unresolvedX86MemoryOffsetError(memory)
}

func x86PlainNOPPrefixRegister(register Reg) bool {
	switch register {
	case CS, DS, ES, FS, GS, TLS:
		return true
	}
	return false
}
