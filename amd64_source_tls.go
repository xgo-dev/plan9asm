package plan9asm

import "strings"

// This is a source-address role, not an ordinary SIB address or permission to
// load memory. Go obj6.progedit may remove the GP base and TLS index altogether;
// asm6.prefixof/vaddr may instead supply a segment and TLS relocation. Selection
// depends on GOOS, GOARCH and -shared, not just the spelling or target triple.
// Callers must return Context for this role until those native facts are bound.
func x86SourceTLSMemoryRole(operand Operand, arch string) bool {
	if operand.Kind != OpMem {
		return false
	}
	memory := operand.Mem
	if memory.Base != TLS && memory.Index != TLS {
		return false
	}
	if memory.OffRaw != "" || memory.IndexExt != "" ||
		memory.Off != int64(int32(memory.Off)) && !(arch == "386" && memory.Off == int64(uint32(memory.Off))) ||
		memory.Segment != "" && memory.Segment != FS && memory.Segment != GS {
		return false
	}
	if memory.Index == "" {
		if memory.Scale != 0 {
			return false
		}
	} else if memory.Scale != 0 && memory.Scale != 1 && memory.Scale != 2 && memory.Scale != 4 && memory.Scale != 8 {
		return false
	}
	if memory.Sym != "" {
		return x86SourceNamedTLSMemoryRole(memory, arch)
	}
	if memory.Base == TLS {
		return memory.Segment == "" && (memory.Index == "" || memory.Index == TLS)
	}
	if memory.Index != TLS {
		return false
	}
	switch memory.Base {
	case "", CS, SS, DS, ES, FS, GS:
		return true // asm6 also accepts an index-only or segment-base annotation.
	default:
		// Direct-TLS progedit may remove any AX..R15 source base before
		// physical mode32 classification. It is still an unbound TLS role.
		return isAMD64YrlRegister(memory.Base)
	}
}

func x86SourceNamedTLSMemoryRole(memory MemRef, arch string) bool {
	if memory.Segment != "" {
		return false
	}
	symbol := strings.TrimSpace(memory.Sym)
	var role string
	for _, suffix := range []string{"(SB)", "(FP)", "(SP)"} {
		if strings.HasSuffix(symbol, suffix) {
			role = suffix
			break
		}
	}
	if role == "" {
		return false
	}
	name, _, valid := parseFP(strings.TrimSuffix(symbol, role) + "(FP)")
	if !valid || name == "" || name[0] >= '0' && name[0] <= '9' || strings.IndexAny(name, "*/&|^%=!$:[]") >= 0 {
		return false
	}
	if arch == "amd64" {
		// Named SB is RIP-based and cannot carry TLS. PARAM/AUTO may carry
		// a TLS Index, but their source Reg must still be absent or SP.
		return role != "(SB)" && (memory.Base == "" || memory.Base == SP) && memory.Index == TLS
	}
	// The 386 named-memory encoder ignores Reg, except that progedit may
	// rewrite it before encoding. Index still has its own address role.
	if memory.Base != "" && !x86SymbolGoRegisterName(string(memory.Base)) {
		return false
	}
	return memory.Index == "" || memory.Index == TLS ||
		memory.Index != SP && isX86YrlRegisterForArch(memory.Index, arch)
}
