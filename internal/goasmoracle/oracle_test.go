package goasmoracle

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
)

func oracleFixture(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	source, object := filepath.Join(dir, "probe.s"), filepath.Join(dir, "probe.o")
	if err := os.WriteFile(source, []byte("#include \"textflag.h\"\nTEXT probe(SB),$0-0\n\tMOVD R0,R1\n\tRET\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return source, object
}

func TestDiagnosticCompleteSourceAndFocus(t *testing.T) {
	source, _ := oracleFixture(t)
	for _, test := range []struct {
		name, suffix string
		focus        int
		want         bool
	}{
		{"direct", ":3: bad operand\n", 3, true},
		{"column", ":3:2: bad operand\n", 3, true},
		{"zero-line", ":0: bad operand\n", 3, false},
		{"overflow-line", ":99999999999999999999: bad operand\n", 3, false},
		{"out-of-range-line", ":9999: bad operand\n", 3, false},
		{"blank-line", ":5: bad operand\n", 0, false},
		{"header", ":1: bad operand\n", 0, false},
		{"TEXT-not-focus", ":2: bad operand\n", 3, false},
		{"RET-not-focus", ":4: bad operand\n", 3, false},
		{"zero-column", ":3:0: bad operand\n", 3, false},
		{"negative-column", ":3:-1: bad operand\n", 3, false},
		{"noncanonical-column", ":3:02: bad operand\n", 3, false},
		{"out-of-range-column", ":3:9999: bad operand\n", 3, false},
		{"no-detail", ":3:2: \n", 3, false},
		{"empty-column", ":3:: bad operand\n", 3, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := SourceDiagnosticLine(source, source+test.suffix, test.focus); got != test.want {
				t.Fatalf("bound=%t, want %t", got, test.want)
			}
		})
	}
}

func TestDiagnosticScannerErrorsDoNotMatch(t *testing.T) {
	for _, source := range []string{"MOVD R0,R1 /*", "MOVD /*", "#include \"x\"", "\x00MOVD R0,R1"} {
		if statementOpcode(source) != "" {
			t.Fatalf("malformed scanner input matched: %q", source)
		}
	}
	if statementOpcode("\tMOVD R0,R1 // comment") != "MOVD" {
		t.Fatal("real opcode lost")
	}
}

func TestDiagnosticAssemblerIdentifierRoles(t *testing.T) {
	// These are real assembler identifiers, not supported instruction names.
	// Their current source-bound Go refusals must retain the diagnostic role.
	for _, test := range []struct {
		opcode string
		bound  bool
		exit   int
	}{
		{"NOT_AN_INSTRUCTION", true, 1},
		{"_NOT_AN_INSTRUCTION", true, 1},
		{"NOT_AN_INSTRUCTION_2", true, 1},
		{"not_an_instruction", true, 1},
		{"無效指令", true, 1},
		{"NOT·AN", true, 1},
		{"NOT∕AN", true, 1},
		{"·NOT", true, 1},
		{"∕NOT", true, 1},
		{"NOT１２", true, 1},
		{"LABEL:", false, 0},
		{"LABEL: NOT_AN_INSTRUCTION", false, 1},
		{"// NOT_AN_INSTRUCTION", false, 0},
		{"/* NOT_AN_INSTRUCTION */", false, 0},
		{"1NOT_AN_INSTRUCTION", false, 1},
		{"/NOT_AN_INSTRUCTION", false, 1},
		{".NOT_AN_INSTRUCTION", false, 1},
		{"MOVD R0,R1 /*", false, 1},
	} {
		t.Run(test.opcode, func(t *testing.T) {
			source, object := oracleFixture(t)
			data := "TEXT probe(SB),$0-0\n\t" + test.opcode + "\n\tRET\n"
			if err := os.WriteFile(source, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			observed, err := goasmcmd.Observe(ctx, filepath.Dir(source),
				append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH=arm64"),
				"go", "tool", "asm", "-o", object, source)
			encoded, _ := json.Marshal(observed)
			t.Logf("ORACLE_CHILD %s", encoded)
			if observed.ExitCode != test.exit || !observed.Waited {
				t.Fatalf("actual original Go diagnostic differs: %+v %v", observed, err)
			}
			if test.bound {
				if !strings.Contains(string(observed.Stderr), source+":2: unrecognized instruction \""+test.opcode+"\"") {
					t.Fatalf("Go did not observe this exact identifier token: %+v", observed)
				}
				if got := statementOpcode("\t" + test.opcode); got != test.opcode {
					t.Fatalf("original identifier token=%q, want %q", got, test.opcode)
				}
				if failure := CheckOutcome(source, object, observed.Stdout, observed.Stderr, err,
					ctx.Err(), false, 2, nil); failure != nil {
					t.Fatalf("real identifier diagnostic lost: %v", failure)
				}
			}
			if got := SourceDiagnosticLine(source, source+":2: bad operand\n", 2); got != test.bound {
				t.Fatalf("statement role=%t, want %t", got, test.bound)
			}
			for _, output := range []string{"foreign" + source + ":2: unrecognized instruction\n",
				source + ":4: unrecognized instruction\n", "asm: assembly failed\n"} {
				if SourceDiagnosticLine(source, output, 2) {
					t.Fatalf("unbound identifier diagnostic matched: %q", output)
				}
			}
			if SourceDiagnosticLine(source, "asm: illegal combination: 00000 ("+source+":2) FOREIGN R0,R1\n", 2) {
				t.Fatal("different listing token matched the original statement")
			}
		})
	}
}

func TestOutcomeSeparateStreamsAndActualExit(t *testing.T) {
	source, object := oracleFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	observed, err := goasmcmd.Observe(ctx, t.TempDir(), append(os.Environ(), "GOASM_ORACLE_EXIT_ONE=1"),
		os.Args[0], "-test.run=^TestOutcomeExitOneFixture$")
	encoded, _ := json.Marshal(observed)
	t.Logf("ORACLE_CHILD %s", encoded)
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 1 || observed.ExitCode != 1 || !observed.Waited {
		t.Fatalf("actual direct exit1 absent: %+v %v", observed, err)
	}
	for _, test := range []struct {
		name           string
		stdout, stderr []byte
		cause, context error
	}{
		{"unknown-exit1", nil, nil, err, nil},
		{"footer", nil, []byte("asm: assembly failed\n"), err, nil},
		{"foreign", nil, []byte("foreign.s:3: bad operand\n"), err, nil},
		{"split-detail", []byte(source + ":3:"), []byte(" bad operand\n"), err, nil},
		{"split-backend", []byte("asm: bad constant\n"), []byte("00000 (" + source + ":3) MOVD R0,R1\n"), err, nil},
		{"panic", []byte(source + ":3: bad operand\n"), []byte("panic: compiler defect\n"), err, nil},
		{"joined-cleanup", nil, []byte(source + ":3: bad operand\n"), errors.Join(err, errors.New("cleanup failed")), nil},
		{"deadline", nil, []byte(source + ":3: bad operand\n"), err, context.DeadlineExceeded},
		{"cancel", nil, []byte(source + ":3: bad operand\n"), err, context.Canceled},
	} {
		t.Run(test.name, func(t *testing.T) {
			failure := CheckOutcome(source, object, test.stdout, test.stderr, test.cause, test.context, false, 3, nil)
			if failure == nil || !strings.Contains(failure.Error(), "infrastructure failure") {
				t.Fatalf("unknown observation accepted: %v", failure)
			}
		})
	}
	if err := CheckOutcome(source, object, nil, []byte(source+":3: bad operand\n"), err, nil, false, 3, nil); err != nil {
		t.Fatalf("real exit1 and exact statement lost: %v", err)
	}
}

func TestOutcomeExitOneFixture(t *testing.T) {
	if os.Getenv("GOASM_ORACLE_EXIT_ONE") == "1" {
		os.Exit(1)
	}
}

func TestSourcePhysicalReadGuards(t *testing.T) {
	source, _ := oracleFixture(t)
	for _, path := range []string{source + ".missing", filepath.Dir(source)} {
		if _, ok := ReadSource(path); ok {
			t.Fatal("nonregular source read succeeded")
		}
	}
	alias := source + ".alias"
	if err := os.Symlink(source, alias); err != nil {
		t.Fatal(err)
	}
	if _, ok := ReadSource(alias); ok {
		t.Fatal("symlink acquired regular-file role")
	}
	large := source + ".large"
	file, err := os.Create(large)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(8<<20 + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := ReadSource(large); ok {
		t.Fatal("over-bound source read succeeded")
	}
}
