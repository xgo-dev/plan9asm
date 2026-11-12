package plan9asm

import "strings"

// A source relocation retains one original symbol plus a signed generated-header
// integer expression, not a different symbol name or a zero displacement.
// Call only after the complete instruction's operand/modifier grammar checks.
func sourceSymbolOffsetNeedsContext(symbol string) bool {
	source := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(symbol), "$"))
	if !strings.HasSuffix(source, "(SB)") {
		return false
	}
	body := strings.TrimSpace(strings.TrimSuffix(source, "(SB)"))
	name, _, resolved := parseSymbolOffset(body)
	if resolved || name == "" {
		return false
	}
	identifier := strings.TrimSuffix(name, "<>")
	if !validPPIdentifier(identifier) {
		return false
	}
	return goIntegerExpressionNeedsContext(strings.TrimSpace(body[len(name):]))
}
