package plan9asm

import "strings"

// Go's jump parser classifies the original case-sensitive token, not the
// shared parser's cross-architecture register aliases. This is only syntax:
// native register, indirect, PC-relative and callee contracts remain separate.
func parseX86BranchIdentifier(op Op, source string) (Operand, bool) {
	name := normalizeInstructionOpcode(op)
	if !strings.HasPrefix(name, "J") && name != "CALL" &&
		!strings.HasPrefix(name, "LOOP") && name != "XBEGIN" {
		return Operand{}, false
	}
	identifier, bare := parseIdent(source)
	if !bare {
		return Operand{}, false
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
