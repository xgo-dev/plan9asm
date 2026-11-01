package plan9asm

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/goasmoracle"
)

func TestGoAssemblerOracleWasmSuffixLabelActualLexicalFamily(t *testing.T) {
	probe := func(t *testing.T, arch, word, suffix string) {
		t.Helper()
		directory := t.TempDir()
		source, object := filepath.Join(directory, "forms.s"), filepath.Join(directory, "forms.o")
		body := "TEXT Probe(SB),4,$0-0\n" + word + suffix + ": NOP\nRET\n"
		if err := os.WriteFile(source, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		stage, cancelStage := runtimeOracleStageContext(t)
		defer cancelStage()
		ctx, cancel := context.WithTimeout(stage, 5*time.Second)
		defer cancel()
		observed, err := goasmcmd.Observe(ctx, directory,
			append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH="+arch),
			"go", "tool", "asm", "-o", object, source)
		encoded, encodeErr := json.Marshal(observed)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		t.Logf("ORACLE_CHILD %s", encoded)
		accepted := arch != "wasm" || suffix == ""
		if !observed.Waited || observed.ExitCode != map[bool]int{true: 0, false: 1}[accepted] || len(observed.Stdout) != 0 {
			t.Fatalf("actual Go lexical outcome differs: %+v %v", observed, err)
		}
		if !accepted {
			message := source + ":2: unrecognized instruction " + strconv.Quote(word) + "\n"
			if !strings.Contains(string(observed.Stderr), message) {
				t.Fatalf("actual first lexical word diagnostic absent: %s", observed.Stderr)
			}
		}
		if failure := goAssemblerOracleOutcome(source, object, observed.Stderr, err, ctx.Err(), accepted, arch); failure != nil {
			t.Errorf("source-bound suffix-label observation lost: %v\n%s", failure, observed.Stderr)
		}
	}
	for _, arch := range []string{"386", "amd64", "arm", "arm64", "wasm"} {
		for _, suffix := range []string{"", ".EQ", ".S", ".EQ.S"} {
			t.Run(arch+"_first"+suffix, func(t *testing.T) {
				probe(t, arch, "first", suffix)
			})
		}
	}
	// These are the Go identifier lexer roles, not mnemonic-name guesses.
	for _, word := range []string{"_first2", "世界", "pkg·first", "path∕first"} {
		t.Run("wasm_"+word, func(t *testing.T) {
			probe(t, "wasm", word, ".EQ.S")
		})
	}
}

func TestGoAssemblerOracleWasmSuffixLabelPositionControls(t *testing.T) {
	source := filepath.Join(t.TempDir(), "forms.s")
	if err := os.WriteFile(source, []byte("TEXT Probe(SB),4,$0-0\nfirst.EQ.S: NOP\nRET\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, output string
		focus        int
	}{
		{"default-has-no-wasm-role", source + ":2: unrecognized instruction \"first\"\n", 2},
		{"wrong-word", source + ":2: unrecognized instruction \"other\"\n", 2},
		{"whole-suffix-is-not-word", source + ":2: unrecognized instruction \"first.EQ.S\"\n", 2},
		{"wrong-physical-line", source + ":3: unrecognized instruction \"first\"\n", 0},
		{"wrong-focus", source + ":2: unrecognized instruction \"first\"\n", 3},
		{"foreign-prefix", "foreign-" + source + ":2: unrecognized instruction \"first\"\n", 2},
		{"noncanonical-line", source + ":02: unrecognized instruction \"first\"\n", 2},
		{"zero-column", source + ":2:0: unrecognized instruction \"first\"\n", 2},
		{"out-of-range-column", source + ":2:999: unrecognized instruction \"first\"\n", 2},
		{"malformed-quote", source + ":2: unrecognized instruction first\n", 2},
		{"message-extension", source + ":2: unrecognized instruction \"first\" extra\n", 2},
		{"footer-only", "asm: assembly failed\n", 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			if goasmoracle.SourceDiagnosticLine(source, test.output, test.focus) {
				t.Fatal("default observer borrowed an unbound or target-only frontend role")
			}
		})
	}
}
