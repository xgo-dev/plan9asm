package goasmoracle

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
)

func TestDiagnosticFrontendPhysicalStatementBoundaries(t *testing.T) {
	for _, test := range []struct {
		name, body, message string
		want                bool
	}{
		{"identifier-after-semicolon", "NOP;1:NOP", `expected identifier, found "1"`, true},
		{"identifier-after-label", "ok:NOP;bad:1:NOP", `expected identifier, found "1"`, true},
		{"first-invalid-not-later", "NOP;1:NOP;2:NOP", `expected identifier, found "2"`, false},
		{"not-an-operand", "MOVQ $1,AX", `expected identifier, found "1"`, false},
		{"duplicate-after-semicolon", "first:NOP;first:NOP", `label "first" multiply defined`, true},
		{"first-duplicate-not-later", "a:NOP;a:NOP;b:NOP;b:NOP", `label "b" multiply defined`, false},
		{"first-duplicate", "a:NOP;a:NOP;b:NOP;b:NOP", `label "a" multiply defined`, true},
		{"same-line-TEXT-reset", "first:NOP;TEXT second(SB),$0-0;first:NOP", `label "first" multiply defined`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			source, _ := oracleFixture(t)
			if err := os.WriteFile(source, []byte("TEXT probe(SB),$0-0\n"+test.body+"\nRET\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if got := SourceDiagnosticLine(source, source+":2: "+test.message+"\n", 2); got != test.want {
				t.Fatalf("complete physical statement boundary join=%t, want %t", got, test.want)
			}
		})
	}
}

func TestDiagnosticFrontendActualSemicolonBoundaries(t *testing.T) {
	for _, test := range []struct{ name, body string }{
		{"identifier", "NOP;1:NOP"},
		{"duplicate", "first:NOP;first:NOP"},
	} {
		t.Run(test.name, func(t *testing.T) {
			source, object := oracleFixture(t)
			if err := os.WriteFile(source, []byte("TEXT probe(SB),$0-0\n"+test.body+"\nRET\n"), 0600); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(5 * time.Second)
			if enclosing, ok := t.Deadline(); ok && enclosing.Before(deadline) {
				deadline = enclosing
			}
			ctx, cancel := context.WithDeadline(context.Background(), deadline)
			defer cancel()
			observed, err := goasmcmd.Observe(ctx, filepath.Dir(source),
				append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH=arm64"),
				"go", "tool", "asm", "-o", object, source)
			encoded, encodeErr := json.Marshal(observed)
			if encodeErr != nil {
				t.Fatal(encodeErr)
			}
			t.Logf("ORACLE_CHILD %s", encoded)
			if !observed.Waited || observed.ExitCode != 1 {
				t.Fatalf("actual frontend outcome differs: %+v %v", observed, err)
			}
			if failure := CheckOutcome(source, object, observed.Stdout, observed.Stderr,
				err, ctx.Err(), false, 2, nil); failure != nil {
				t.Fatalf("actual physical-line frontend observation lost: %v", failure)
			}
		})
	}
}
