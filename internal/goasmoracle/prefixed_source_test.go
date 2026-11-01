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

func TestDiagnosticBackendPrefixedSourcePositions(t *testing.T) {
	source, _ := oracleFixture(t)
	for _, test := range []struct {
		name, output string
		focus        int
		want         bool
	}{
		{"plain", source + ":3: bad operand\n", 3, true},
		{"backend", "asm: " + source + ":3: bad operand\n", 3, true},
		{"backend-column", "asm: " + source + ":3:2: bad operand\n", 3, true},
		{"foreign-path", "asm: foreign" + source + ":3: bad operand\n", 3, false},
		{"embedded-path", "asm: wrapper " + source + ":3: bad operand\n", 3, false},
		{"foreign-backend", "other: " + source + ":3: bad operand\n", 3, false},
		{"missing-space", "asm:" + source + ":3: bad operand\n", 3, false},
		{"repeated-prefix", "asm: asm: " + source + ":3: bad operand\n", 3, false},
		{"wrong-focus", "asm: " + source + ":4: bad operand\n", 3, false},
		{"zero-line", "asm: " + source + ":0: bad operand\n", 0, false},
		{"noncanonical-line", "asm: " + source + ":03: bad operand\n", 0, false},
		{"header", "asm: " + source + ":1: bad operand\n", 0, false},
		{"blank", "asm: " + source + ":5: bad operand\n", 0, false},
		{"zero-column", "asm: " + source + ":3:0: bad operand\n", 3, false},
		{"no-detail", "asm: " + source + ":3:2: \n", 3, false},
		{"footer", "asm: assembly failed\n", 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := SourceDiagnosticLine(source, test.output, test.focus); got != test.want {
				t.Fatalf("source diagnostic=%t, want %t: %q", got, test.want, test.output)
			}
		})
	}
}

func TestDiagnosticActualBackendSymbolRedeclaration(t *testing.T) {
	for _, arch := range []string{"386", "amd64", "arm", "arm64", "wasm"} {
		t.Run(arch, func(t *testing.T) {
			source, object := oracleFixture(t)
			data := "TEXT probe(SB),$0-0\nRET\nGLOBL probe(SB),8,$8\n"
			if err := os.WriteFile(source, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(5 * time.Second)
			if end, ok := t.Deadline(); ok && end.Before(deadline) {
				deadline = end
			}
			ctx, cancel := context.WithDeadline(context.Background(), deadline)
			defer cancel()
			observed, err := goasmcmd.Observe(ctx, filepath.Dir(source),
				append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH="+arch),
				"go", "tool", "asm", "-o", object, source)
			encoded, encodeErr := json.Marshal(observed)
			if encodeErr != nil {
				t.Fatal(encodeErr)
			}
			t.Logf("ORACLE_CHILD %s", encoded)
			if !observed.Waited || observed.ExitCode != 1 || err == nil || ctx.Err() != nil {
				t.Fatalf("actual Go symbol rejection absent: %+v %v", observed, err)
			}
			if !strings.Contains(string(observed.Stderr), "asm: "+source+":3: symbol probe redeclared") {
				t.Fatalf("actual source-bound backend diagnostic absent: %s", observed.Stderr)
			}
			if failure := CheckOutcome(source, object, observed.Stdout, observed.Stderr,
				err, ctx.Err(), false, 3, nil); failure != nil {
				t.Fatal(failure)
			}
		})
	}
}
