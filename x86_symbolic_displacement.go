package plan9asm

import (
	"fmt"
	"strings"
)

// Go's symbolReference consumes one symbol, optional ABI/static attributes,
// and then the entire signed constant expression before (SB). An unresolved
// suffix must not become part of a different external symbol, even if a later
// suffix is numerical (name+UNKNOWN+4). Keep this before raw normalization and
// every lowerer, shared by the inventory probe and the full translation APIs.
func validateX86SymbolDisplacement(operand Operand) error {
	var source string
	switch operand.Kind {
	case OpSym:
		source = strings.TrimSpace(operand.Sym)
	case OpMem:
		source = strings.TrimSpace(operand.Mem.Sym)
	default:
		return nil
	}
	source = strings.TrimSpace(strings.TrimPrefix(source, "*"))
	source = strings.TrimSpace(strings.TrimPrefix(source, "$"))
	group := x86SymbolPseudoGroup.FindStringSubmatchIndex(source)
	if group == nil || source[group[2]:group[3]] != "SB" {
		return nil
	}
	prefix := strings.TrimSpace(source[:group[0]])
	separator := strings.IndexAny(prefix, "+-")
	if separator < 1 {
		return nil
	}
	expression := strings.TrimSpace(prefix[separator:])
	if _, resolved := parseImmExpr(expression); resolved {
		return nil
	}
	name := strings.TrimSpace(prefix[:separator])
	for _, attribute := range []string{"<>", "<ABI0>", "<ABIInternal>"} {
		name = strings.TrimSuffix(name, attribute)
	}
	if validPPIdentifier(name) && memoryOffsetExpressionNeedsContext(expression) {
		return fmt.Errorf("%w: unresolved x86 symbol displacement %q in %q", ErrProbeNeedsContext, expression, source)
	}
	return fmt.Errorf("invalid x86 symbol displacement %q in %q", expression, source)
}
