package plan9asm

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var x86SymbolPseudoGroup = regexp.MustCompile(`\(\s*(FP|SP|SB|PC)\s*\)`)
var x86SymbolGIndex = regexp.MustCompile(`\(\s*g\s*\*`)

// The group after a named pseudo base is not always an index. Go's operand
// parser sets Reg for (SI), but Index for (SI*1); a third group supplies Index
// only when the second supplied Reg. Retain that distinction even where a
// native encoder rejects or ignores Reg. Parsing does not establish storage.
func parseX86SymbolIndexedMemory(source string) (memory MemRef, matched bool, err error) {
	source = strings.TrimSpace(source)
	group := x86SymbolPseudoGroup.FindStringSubmatchIndex(source)
	if group == nil || strings.TrimSpace(source[group[1]:]) == "" {
		return MemRef{}, false, nil
	}
	matched = true
	role := source[group[2]:group[3]]
	if role == "PC" {
		return MemRef{}, true, fmt.Errorf("x86 PC-relative branch cannot have an extra address register: %q", source)
	}
	prefix := strings.TrimSpace(source[:group[0]])
	if role == "SP" {
		if _, constant := parseImmExpr(prefix); prefix == "" || constant {
			return MemRef{}, false, nil // Physical SP, including decoder syntax.
		}
	}
	name, _, valid := parseFP(prefix + "(FP)")
	if !valid || name == "" || name[0] >= '0' && name[0] <= '9' || strings.IndexAny(name, "*/&|^%=!$:[]") >= 0 {
		return MemRef{}, true, fmt.Errorf("x86 indexed pseudo base requires a symbol and constant displacement: %q", source)
	}
	memory.Sym = prefix + "(" + role + ")"
	rest := strings.TrimSpace(source[group[1]:])
	register, scale, scaled, rest, err := parseX86SymbolRegisterGroup(rest)
	if err != nil {
		return MemRef{}, true, err
	}
	if scaled {
		memory.Index, memory.Scale = register, scale
		if rest != "" {
			return MemRef{}, true, fmt.Errorf("x86 scaled index must be the final address group: %q", source)
		}
		return memory, true, nil
	}
	memory.Base = register
	if rest != "" {
		register, scale, _, rest, err = parseX86SymbolRegisterGroup(rest)
		if err != nil {
			return MemRef{}, true, err
		}
		memory.Index, memory.Scale = register, scale
		if rest != "" {
			return MemRef{}, true, fmt.Errorf("x86 address has more than a base and index group: %q", source)
		}
	}
	return memory, true, nil
}

func parseX86SymbolRegisterGroup(source string) (register Reg, scale int64, scaled bool, rest string, err error) {
	bad := func() (Reg, int64, bool, string, error) {
		return "", 0, false, "", fmt.Errorf("invalid x86 symbolic address register/scale group: %q", source)
	}
	if !strings.HasPrefix(source, "(") {
		return bad()
	}
	end := strings.IndexByte(source, ')')
	if end < 0 {
		return bad()
	}
	inner := strings.TrimSpace(source[1:end])
	rest = strings.TrimSpace(source[end+1:])
	name := inner
	if before, after, found := strings.Cut(inner, "*"); found {
		name, scaled = strings.TrimSpace(before), true
		// parseScale consumes one token's spelling, not an integer expression.
		// In particular 01, 0x1, +1 and (1) are not the decimal token "1".
		switch strings.TrimSpace(after) {
		case "1":
			scale = 1
		case "2":
			scale = 2
		case "4":
			scale = 4
		case "8":
			scale = 8
		default:
			return bad()
		}
	}
	if name == "FP" || name == "SB" || name == "PC" {
		return "", 0, false, "", fmt.Errorf("%w: a second pseudo register overwrites the original named address role: %q", ErrProbeNeedsContext, source)
	}
	if name == "g" {
		return "", 0, false, "", fmt.Errorf("%w: named x86 g annotation requires its original 386/amd64 source mode", ErrProbeNeedsContext)
	}
	if !x86SymbolGoRegisterName(name) {
		return bad()
	}
	return Reg(name), scale, scaled, rest, nil
}

// This finite spelling grammar is Go's x86.Register inventory, not an LLVM
// register permission. In particular a named 386 operand can annotate a Reg
// that the encoder ignores, even when it is not a physical 386 GP register.
func x86SymbolGoRegisterName(name string) bool {
	switch name {
	case "AL", "CL", "DL", "BL", "SPB", "BPB", "SIB", "DIB",
		"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI",
		"AH", "CH", "DH", "BH", "CS", "SS", "DS", "ES", "FS", "GS",
		"GDTR", "IDTR", "LDTR", "MSW", "TASK", "TLS", "MAXREG":
		return true
	}
	for _, bank := range []struct {
		prefix, suffix string
		min, max       int
	}{
		{"R", "", 8, 15}, {"R", "B", 8, 15},
		{"F", "", 0, 7}, {"M", "", 0, 7}, {"K", "", 0, 7},
		{"X", "", 0, 31}, {"Y", "", 0, 31}, {"Z", "", 0, 31},
		{"CR", "", 0, 15}, {"DR", "", 0, 7}, {"TR", "", 0, 7},
	} {
		if !strings.HasPrefix(name, bank.prefix) || !strings.HasSuffix(name, bank.suffix) {
			continue
		}
		number := strings.TrimSuffix(strings.TrimPrefix(name, bank.prefix), bank.suffix)
		value, err := strconv.Atoi(number)
		if err == nil && value >= bank.min && value <= bank.max && number == strconv.Itoa(value) {
			return true
		}
	}
	return false
}
