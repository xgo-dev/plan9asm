package plan9asm

import (
	"strings"
	"unicode/utf8"
)

// cmd/asm's TYPE_BRANCH keeps the evaluated displacement and discards any
// preceding symbol. This does not resolve a symbol or an unknown displacement.
func parseX86NamedPCBranchTarget(op Op, source string) (Operand, bool) {
	if op != OpJMP && op != "XBEGIN" && !isAMD64ConditionalBranch(op) {
		return Operand{}, false
	}
	first, _ := utf8.DecodeRuneInString(source)
	if !ppIdentRune(first, 0) {
		return Operand{}, false
	}
	group := x86SymbolPseudoGroup.FindStringSubmatchIndex(source)
	if group == nil || group[1] != len(source) || source[group[2]:group[3]] != string(PC) {
		return Operand{}, false
	}
	prefix := strings.TrimSpace(source[:group[0]])
	name, displacement := prefix, ""
	if sign := strings.IndexAny(prefix, "+-"); sign >= 0 {
		name, displacement = strings.TrimSpace(prefix[:sign]), prefix[sign:]
	}
	if symbol, static, ok := strings.Cut(name, "<"); ok && strings.TrimSpace(static) == ">" {
		name = strings.TrimSpace(symbol)
	}
	if !validPPIdentifier(name) || x86SymbolGoRegisterName(name) ||
		name == "g" || name == "SB" || name == "FP" || name == "PC" {
		return Operand{}, false
	}
	var offset uint64
	if displacement != "" {
		var ok bool
		offset, ok = parseImmExpr(displacement)
		if !ok {
			return Operand{}, false
		}
	}
	return Operand{Kind: OpMem, Mem: MemRef{Base: PC, Off: int64(offset)}}, true
}

// Go's jump parser classifies the original case-sensitive token, not the
// shared parser's cross-architecture register aliases. This is only syntax:
// native register, indirect, PC-relative and callee contracts remain separate.
func parseX86BranchOperand(op Op, source string) (Operand, bool) {
	name := normalizeInstructionOpcode(op)
	if !strings.HasPrefix(name, "J") && name != "CALL" &&
		!strings.HasPrefix(name, "LOOP") && name != "XBEGIN" {
		return Operand{}, false
	}
	identifier, bare := parseIdent(source)
	if !bare {
		return parseX86NamedPCBranchTarget(op, source)
	}
	if identifier == "g" {
		// Preserve the shared parser's existing AMD64 alias. The actual
		// source mode still owns its distinct 386 applicability checks.
		return Operand{Kind: OpReg, Reg: "R14"}, true
	}
	if x86SymbolGoRegisterName(identifier) || identifier == "SB" || identifier == "FP" || identifier == "PC" {
		return Operand{Kind: OpReg, Reg: Reg(identifier)}, true
	}
	return Operand{Kind: OpIdent, Ident: identifier}, true
}
