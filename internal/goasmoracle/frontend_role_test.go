package goasmoracle

import (
	"os"
	"strconv"
	"testing"
)

// These are diagnostic-join controls, not claims that a fabricated diagnostic
// came from Go. The original parser roots provide the separate actual oracle.
func TestDiagnosticFrontendOriginalTokenBinding(t *testing.T) {
	for _, test := range []struct {
		name, body, message string
		line, focus         int
		want                bool
	}{
		{"integer", "1: NOP", `expected identifier, found "1"`, 2, 2, true},
		{"string", `"name": NOP`, `expected identifier, found "\"name\""`, 2, 2, true},
		{"colon", ": NOP", `expected identifier, found ":"`, 2, 2, true},
		{"float", "1.0: NOP", `expected identifier, found "1.0"`, 2, 2, true},
		{"char", "'x': NOP", `expected identifier, found "'x'"`, 2, 2, true},
		{"plus", "+name: NOP", `expected identifier, found "+"`, 2, 2, true},
		{"integer-not-prefix", "12: NOP", `expected identifier, found "1"`, 2, 2, false},
		{"string-not-decoded-value", `"name": NOP`, `expected identifier, found "name"`, 2, 2, false},
		{"wrong-token", "1: NOP", `expected identifier, found ":"`, 2, 2, false},
		{"token-in-operand", "MOVQ $1,AX", `expected identifier, found "1"`, 2, 2, false},
		{"valid-identifier", "name: NOP", `expected identifier, found "name"`, 2, 2, false},
		{"header-is-not-token", "1: NOP", `expected identifier, found "1"`, 1, 2, false},
		{"wrong-focus", "1: NOP", `expected identifier, found "1"`, 2, 3, false},
		{"wrong-line", "1: NOP", `expected identifier, found "1"`, 3, 0, false},
		{"unknown-nonidentifier-message", "1: NOP", "bad source", 2, 2, false},
		{"noncanonical-quote", "1: NOP", `expected identifier, found "\x31"`, 2, 2, false},
		{"message-tail", "1: NOP", `expected identifier, found "1" extra`, 2, 2, false},
		{"unterminated-comment", "/* broken", `expected identifier, found "/"`, 2, 2, false},
		{"comment-only", "// 1: NOP", `expected identifier, found "1"`, 2, 2, false},
		{"unknown-identifier-control", "NOT_AN_INSTRUCTION", `unrecognized instruction "NOT_AN_INSTRUCTION"`, 2, 2, true},
		{"duplicate-inline", "first: first: NOP", `label "first" multiply defined`, 2, 2, true},
		{"duplicate-pending", "first: first:\nRET", `label "first" multiply defined`, 3, 3, true},
		{"duplicate-separated", "first: NOP\nfirst: NOP", `label "first" multiply defined`, 3, 3, true},
		{"duplicate-wrong-name", "first: first:\nRET", `label "other" multiply defined`, 3, 3, false},
		{"duplicate-absent", "RET", `label "first" multiply defined`, 2, 2, false},
		{"duplicate-label-in-comment", "// first: first:\nRET", `label "first" multiply defined`, 3, 3, false},
		{"duplicate-late-definition", "RET\nfirst: first: NOP", `label "first" multiply defined`, 2, 2, false},
		{"duplicate-new-text", "first: NOP\nTEXT second(SB),$0-0\nfirst: NOP", `label "first" multiply defined`, 4, 4, false},
		{"duplicate-message-tail", "first: first:\nRET", `label "first" multiply defined extra`, 3, 3, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			source, _ := oracleFixture(t)
			text := "TEXT probe(SB),$0-0\n" + test.body + "\nRET\n"
			if err := os.WriteFile(source, []byte(text), 0600); err != nil {
				t.Fatal(err)
			}
			output := source + ":" + strconv.Itoa(test.line) + ": " + test.message + "\n"
			if got := SourceDiagnosticLine(source, output, test.focus); got != test.want {
				t.Fatalf("original frontend token/label join=%t, want %t", got, test.want)
			}
			if SourceDiagnosticLine(source, "foreign"+output, test.focus) {
				t.Fatal("foreign source prefix acquired a frontend role")
			}
		})
	}
}

// A target-free parser must never silently become a global opcode alias map.
// The new x86 diagnostic adapter will be tested separately with exact targets.
func TestDiagnosticDefaultDoesNotCanonicalizeBackendOpcodes(t *testing.T) {
	for _, test := range []struct{ source, listing string }{
		{"PADDD M0,X1", "PADDL M0, X1"},
		{"PADDD.Z X0,X1", "PADDL.Z X0, X1"},
		{"MOVD X0,M1", "MOVQ X0, M1"},
		{"VMOVSS $0.0,K1,X0", "XORPS X0, K1, X0"},
		{"VMOVSD.Z $0.0,X1,K7,X0", "XORPS.Z X0, X1, K7, X0"},
	} {
		t.Run(test.source, func(t *testing.T) {
			source, _ := oracleFixture(t)
			if err := os.WriteFile(source, []byte("TEXT probe(SB),$0-0\n"+test.source+"\nRET\n"), 0600); err != nil {
				t.Fatal(err)
			}
			output := "asm: bad: invalid instruction: 00000 (" + source + ":2)\t" + test.listing + "\n"
			if ListingBindsSource(source, "2", "00000", test.listing) || SourceDiagnosticLine(source, output, 2) {
				t.Fatal("target-free parser canonicalized a backend opcode")
			}
		})
	}
}
