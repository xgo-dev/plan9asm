package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Independent cmd/asm expr/term/factor directory. Expected uint64 results
// are not computed with parseImmExpr or another copy of the implementation.
// A real Go GLOBL at +(expression)-(expected) must independently accept zero.
var goASMIntegerGrammarValues = []struct {
	name, expression string
	want             uint64
}{
	{"zero", "0", 0},
	{"decimal-underscores", "1_2_3", 123},
	{"hexadecimal", "0xff", 255},
	{"binary", "0b1_001", 9},
	{"explicit-octal", "0o17", 15},
	{"legacy-octal", "077", 63},
	{"unary-plus", "+1", 1},
	{"unary-minus", "-1", ^uint64(0)},
	{"adjacent-plus", "++1", 1},
	{"adjacent-minus", "--1", 1},
	{"nested-signs", "+(-(-1))", 1},
	{"complement", "~0", ^uint64(0)},
	{"nested-complement", "~~0", 0},
	{"uint64-wrap", "0xffff_ffff_ffff_ffff+1", 0},
	{"rune-tilde", "'~'", 126},
	{"rune-caret", "'^'", 94},
	{"rune-plus", "'+'", 43},
	{"rune-minus", "'-'", 45},
	{"rune-left-shift-character", "'<'", 60},
	{"rune-right-shift-character", "'>'", 62},
	{"rune-divide-character", "'/'", 47},
	{"rune-comma-character", "','", 44},
	{"rune-open-parenthesis", "'('", 40},
	{"rune-close-parenthesis", "')'", 41},
	{"rune-semicolon-character", "';'", 59},
	{"rune-double-quote", `'"'`, 34},
	{"rune-backtick", "'`'", 96},
	{"rune-hexadecimal-escape", "'\\x7e'", 126},
	{"rune-unicode-escape", "'\\u007e'", 126},
	{"rune-unicode", "'世'", 19990},
	{"rune-escaped-quote", `'\''`, 39},
	{"rune-escaped-backslash", "'\\\\'", 92},
	{"parenthesized-products", "(1+2)*(3+4)", 21},
	{"left-associated-subtraction", "17-3-2", 12},
	{"product-wrap", "0x8000000000000000*2", 0},
	{"division", "17/3", 5},
	{"remainder", "17%3", 2},
	{"high-bit-divisor", "1/~0", 0},
	{"high-bit-modulus", "1%~0", 1},
	{"left-associated-expr", "1|2^3", 0},
	{"term-before-expr", "17&3^1", 0},
	{"right-shift-recursive-product", "8>>1*2", 2},
	{"right-shift-recursive-shift", "64>>1>>2", 64},
	{"right-shift-recursive-and", "64>>1&3", 32},
	{"right-shift-recursive-division", "64>>3/2", 32},
	{"right-shift-recursive-remainder", "64>>3%2", 32},
	{"right-shift-recursive-left-shift", "64>>1<<2", 4},
	{"right-shift-consumes-left-shift-remainder", "64>>1<<2*3", 12},
	{"right-shift-after-product", "8*2>>1*2", 4},
	{"right-shift-expr-boundary", "64>>3+1", 9},
	{"left-shift-expr-boundary", "1<<3+1", 9},
	{"parenthesized-left-shift-term", "(1<<3)*2", 16},
	{"left-shift-sixty-four", "1<<64", 0},
	{"right-shift-sixty-four", "1>>64", 0},
	{"right-shift-recursive-zero-count", "1>>64*0", 1},
}

var goASMIntegerGrammarInvalid = []struct{ name, expression string }{
	{"negative-left-shift", "1<<-1"},
	{"negative-right-shift", "1>>-1"},
	{"high-bit-division", "~0/2"},
	{"high-bit-remainder", "~0%2"},
	{"high-bit-right-shift", "(-1)>>1"},
	{"computed-high-bit-division", "(1<<63)/2"},
	{"computed-high-bit-remainder", "(1<<63)%2"},
	{"computed-high-bit-right-shift", "(1<<63)>>1"},
	{"division-zero", "1/0"},
	{"remainder-zero", "1%0"},
	{"Go-only-and-not", "1&^1"},
	{"Go-only-and-not-nonzero", "7&^3"},
	{"Go-only-unary-caret", "^0+1"},
	{"left-shift-remaining-product", "1<<1*0"},
	{"left-shift-remaining-and", "1<<1&0"},
	{"left-shift-remaining-shift", "1<<1<<0"},
	{"unknown-identifiers", "UNKNOWN-UNKNOWN"},
	{"unclosed-parenthesis", "(1"},
	{"remaining-literal", "(1)2"},
	{"uint64-overflow-literal", "18446744073709551616"},
	{"float-in-integer-expression", "1.0-1.0"},
	{"rune-invalid-UTF8-byte", "'\\377'"},
}

func TestGoASMIntegerGrammarBoundsAndUnresolvedQueryIdentity(t *testing.T) {
	for _, expression := range []string{
		strings.Repeat("(", 32) + "1" + strings.Repeat(")", 32),
		strings.Repeat("+", 32) + "1",
	} {
		if value, valid := parseImmExpr(expression); !valid || value != 1 {
			t.Fatal("ordinary bounded nesting lost its complete numerical value", expression, value, valid)
		}
	}
	for _, row := range []struct{ name, expression string }{
		{"bytes", "1" + strings.Repeat("/*x*/", 14000)},
		{"tokens", "1" + strings.Repeat("+1", 3000)},
		{"depth", strings.Repeat("+", 256) + "1"},
		{"unknown-then-zero", "UNKNOWN+0"},
		{"invalid-then-zero", "(1&^1)+0"},
		{"invalid-shift-then-zero", "(1<<1*0)+0"},
	} {
		t.Run(row.name, func(t *testing.T) {
			if value, valid := parseImmExpr(row.expression); valid {
				t.Fatal("an unresolved or over-budget expression acquired a numerical result", value)
			}
			original := "literal<>+(" + row.expression + ")"
			if name, offset := SplitSymbolOffset(original); name != original || offset != 0 {
				t.Fatal("the public unresolved query lost its original identity", name, offset)
			}
			if _, _, valid := parseSBRef(original + "(SB)"); valid {
				t.Fatal("an unresolved expression acquired an SB reference")
			}
			if _, err := parseGLOBLStmt(original + "(SB),8,$8"); err == nil {
				t.Fatal("an unresolved expression acquired a concrete declaration")
			}
		})
	}
}

func goASMIntegerZeroOffset(expression string, value uint64) string {
	return fmt.Sprintf("+(%s)-%d", expression, value)
}

func TestGoASMIntegerGrammarSharedScalarAndSymbolConsumers(t *testing.T) {
	for _, row := range goASMIntegerGrammarValues {
		t.Run(row.name, func(t *testing.T) {
			t.Run("scalar", func(t *testing.T) {
				if value, ok := parseImmExpr(row.expression); !ok || value != row.want {
					t.Fatalf("official integer grammar %q = %#x, %v; want %#x", row.expression, value, ok, row.want)
				}
			})
			t.Run("DATA-value", func(t *testing.T) {
				datum, err := parseDATAStmt(ArchAMD64, "literal<>(SB)/8,$("+row.expression+")")
				if err != nil || datum.Sym != "literal<>" || datum.Off != 0 || datum.Value != row.want || datum.Addr != "" || datum.Payload != nil {
					t.Fatal("DATA did not retain the exact official integer expression", datum, err)
				}
			})
			t.Run("DATA-displacement", func(t *testing.T) {
				datum, err := parseDATAStmt(ArchAMD64, "literal<>"+goASMIntegerZeroOffset(row.expression, row.want)+"(SB)/8,$17")
				if err != nil || datum.Sym != "literal<>" || datum.Off != 0 || datum.Value != 17 {
					t.Fatal("DATA zero displacement changed the underlying symbol/image", datum, err)
				}
			})
			t.Run("SB-displacement", func(t *testing.T) {
				name, offset, ok := parseSBRef("literal<>+(" + row.expression + ")(SB)")
				if !ok || name != "literal<>" || uint64(offset) != row.want {
					t.Fatalf("SB reference lost actual integer addend: %q, %#x, %v; want %#x", name, uint64(offset), ok, row.want)
				}
			})
			t.Run("GLOBL-zero", func(t *testing.T) {
				global, err := parseGLOBLStmt("literal<>" + goASMIntegerZeroOffset(row.expression, row.want) + "(SB),8,$8")
				if err != nil || global.Sym != "literal<>" || global.Size != 8 {
					t.Fatal("a real Go zero displacement lost its declaration identity", global, err)
				}
			})
		})
	}
}

func goASMIntegerGrammarCompleteSource(pointerSize int) (string, []globlZeroAddendSymbol) {
	var source strings.Builder
	var symbols []globlZeroAddendSymbol
	for index, row := range goASMIntegerGrammarValues {
		value := fmt.Sprintf("expr_value_%02d", index)
		zero := fmt.Sprintf("zero_globl_expr_%02d", index)
		address := fmt.Sprintf("expr_address_%02d", index)
		offset := goASMIntegerZeroOffset(row.expression, row.want)
		fmt.Fprintf(&source, "DATA %s<>(SB)/8,$(%s)\nGLOBL %s<>(SB),8,$8\n", value, row.expression, value)
		fmt.Fprintf(&source, "DATA %s<>%s(SB)/8,$0x1122334455667788\n", zero, offset)
		fmt.Fprintf(&source, "DATA %s<>+16(SB)/8,$\"a+0;b\"\n", zero)
		fmt.Fprintf(&source, "DATA %s<>+36(SB)/4,$0xa1b2c3d4\nDATA %s<>+71(SB)/1,$0x5a\n", zero, zero)
		fmt.Fprintf(&source, "GLOBL %s<>%s(SB),8,$72\n", zero, offset)
		fmt.Fprintf(&source, "DATA %s<>(SB)/%d,$%s<>%s(SB)\nGLOBL %s<>(SB),8,$%d\n", address, pointerSize, zero, offset, address, pointerSize)
		symbols = append(symbols, globlZeroAddendSymbol{name: zero, sourceName: zero + "<>", caseName: row.name, readOnly: true, local: true})
	}
	source.WriteString("TEXT ·Probe(SB),4,$0-0\nRET\n")
	return source.String(), symbols
}
