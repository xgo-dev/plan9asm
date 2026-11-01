package goasmoracle

import (
	"fmt"
	"os"
	"testing"
)

// These fabricated joins exercise the observation schema, not Go acceptance,
// instruction support or native execution. Actual Go is a separate fixture.
func TestDiagnosticUnrecognizedInstructionWordAndDialect(t *testing.T) {
	for _, test := range []struct {
		name, body, message string
		line, column, focus int
		wasm, want          bool
	}{
		{"bare-word", "BAD_WORD", `unrecognized instruction "BAD_WORD"`, 2, 0, 2, false, true},
		{"opcode-suffix-word", "BAD_WORD.EQ.S", `unrecognized instruction "BAD_WORD"`, 2, 0, 2, false, true},
		{"opcode-suffix-not-whole-word", "BAD_WORD.EQ.S", `unrecognized instruction "BAD_WORD.EQ.S"`, 2, 0, 2, false, false},
		{"bare-label-is-not-word", "first: NOP", `unrecognized instruction "first"`, 2, 0, 2, true, false},
		{"default-suffix-label-is-not-word", "first.EQ.S: NOP", `unrecognized instruction "first"`, 2, 0, 2, false, false},
		{"wasm-suffix-word", "first.EQ.S: NOP", `unrecognized instruction "first"`, 2, 0, 2, true, true},
		{"wasm-after-label", "outer: first.EQ.S: NOP", `unrecognized instruction "first"`, 2, 0, 2, true, true},
		{"default-after-label", "outer: first.EQ.S: NOP", `unrecognized instruction "first"`, 2, 0, 2, false, false},
		{"unknown-after-label", "first: BAD_WORD", `unrecognized instruction "BAD_WORD"`, 2, 0, 2, false, true},
		{"unknown-after-semicolon", "NOP; BAD_WORD", `unrecognized instruction "BAD_WORD"`, 2, 0, 2, false, true},
		{"wasm-after-semicolon", "NOP; first.EQ.S: NOP", `unrecognized instruction "first"`, 2, 0, 2, true, true},
		{"invalid-token-stops-parser", "1: NOP; first.EQ.S: NOP", `unrecognized instruction "first"`, 2, 0, 2, true, false},
		{"operand-token-is-not-word", "MOVQ $first,AX", `unrecognized instruction "first"`, 2, 0, 2, true, false},
		{"string-token-is-not-word", `DATA blob<>+0(SB)/8,$"first.EQ.S"`, `unrecognized instruction "first"`, 2, 0, 2, true, false},
		{"comment-token-is-not-word", "// first.EQ.S: NOP", `unrecognized instruction "first"`, 2, 0, 2, true, false},
		{"multiline-comment-is-not-word", "/*\nfirst.EQ.S: NOP\n*/", `unrecognized instruction "first"`, 3, 0, 3, true, false},
		{"malformed-comment", "/* first.EQ.S: NOP", `unrecognized instruction "first"`, 2, 0, 2, true, false},
		{"label-only-is-not-word", "first:", `unrecognized instruction "first"`, 2, 0, 2, true, false},
		{"wrong-token", "first.EQ.S: NOP", `unrecognized instruction "other"`, 2, 0, 2, true, false},
		{"full-suffix-is-not-word", "first.EQ.S: NOP", `unrecognized instruction "first.EQ.S"`, 2, 0, 2, true, false},
		{"correct-column", "  first.EQ.S: NOP", `unrecognized instruction "first"`, 2, 3, 2, true, true},
		{"wrong-column", "  first.EQ.S: NOP", `unrecognized instruction "first"`, 2, 4, 2, true, false},
		{"out-of-range-column", "first.EQ.S: NOP", `unrecognized instruction "first"`, 2, 999, 2, true, false},
		{"wrong-physical-line", "first.EQ.S: NOP", `unrecognized instruction "first"`, 3, 0, 0, true, false},
		{"wrong-focus", "first.EQ.S: NOP", `unrecognized instruction "first"`, 2, 0, 3, true, false},
		{"unquoted-token", "first.EQ.S: NOP", "unrecognized instruction first", 2, 0, 2, true, false},
		{"noncanonical-quote", "first.EQ.S: NOP", `unrecognized instruction "\x66irst"`, 2, 0, 2, true, false},
		{"message-tail", "first.EQ.S: NOP", `unrecognized instruction "first" extra`, 2, 0, 2, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			source, _ := oracleFixture(t)
			body := "TEXT Probe(SB),4,$0-0\n" + test.body + "\nRET\n"
			if err := os.WriteFile(source, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			position := fmt.Sprintf("%d", test.line)
			if test.column != 0 {
				position += fmt.Sprintf(":%d", test.column)
			}
			output := source + ":" + position + ": " + test.message + "\n"
			observe := SourceDiagnosticLine
			if test.wasm {
				observe = WasmSourceDiagnosticLine
			}
			if got := observe(source, output, test.focus); got != test.want {
				t.Fatalf("original frontend word join=%t, want %t", got, test.want)
			}
			if observe(source, "foreign-"+output, test.focus) {
				t.Fatal("foreign path prefix acquired the frontend word role")
			}
		})
	}
}
