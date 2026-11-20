package goasmoracle

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
)

func TestDiagnosticFrontendActualOriginalSources(t *testing.T) {
	for _, test := range []struct {
		name, body string
		accepted   bool
	}{
		{"integer", "1: NOP\n", false},
		{"float", "1.0: NOP\n", false},
		{"string", "\"name\": NOP\n", false},
		{"char", "'x': NOP\n", false},
		{"plus", "+name: NOP\n", false},
		{"colon", ": NOP\n", false},
		{"duplicate-inline", "first: first: NOP\n", false},
		{"duplicate-pending", "first: first:\n", false},
		{"duplicate-separated", "first: NOP\nfirst: NOP\n", false},
		{"cross-TEXT", "first: NOP\nTEXT second(SB),$0-0\nfirst: NOP\n", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			source, object := oracleFixture(t)
			data := "TEXT probe(SB),$0-0\n" + test.body + "RET\n"
			if err := os.WriteFile(source, []byte(data), 0600); err != nil {
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
			exit := 1
			if test.accepted {
				exit = 0
			}
			if !observed.Waited || observed.ExitCode != exit {
				t.Fatalf("actual frontend outcome differs: %+v %v", observed, err)
			}
			if !test.accepted {
				role := "expected identifier, found "
				if strings.HasPrefix(test.name, "duplicate-") {
					role = "label \"first\" multiply defined"
				}
				if !strings.Contains(string(observed.Stderr), role) {
					t.Fatalf("original frontend role absent: %+v", observed)
				}
			}
			if failure := CheckOutcome(source, object, observed.Stdout, observed.Stderr,
				err, ctx.Err(), test.accepted, 0, nil); failure != nil {
				t.Fatalf("actual frontend observation lost: %v", failure)
			}
		})
	}
}
