package goasmoracle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
)

func TestDiagnosticZeroOperandModeListings(t *testing.T) {
	// This full ynone family covers mode-restricted P32/Py rows and their
	// Pe word controls. Syntax/object observation grants no native execution.
	want := map[string]string{
		"LEAVEW": "Pe", "LEAVEL": "P32", "LEAVEQ": "Py",
		"PUSHAW": "Pe", "PUSHAL": "P32",
		"POPAW": "Pe", "POPAL": "P32",
		"PUSHFW": "Pe", "PUSHFL": "P32", "PUSHFQ": "Py",
		"POPFW": "Pe", "POPFL": "P32", "POPFQ": "Py",
	}
	table := filepath.Join(runtime.GOROOT(), "src", "cmd", "internal", "obj", "x86", "asm6.go")
	data, ok := ReadSource(table)
	if !ok {
		t.Fatal("complete original Go x86 table unavailable")
	}
	rows := regexp.MustCompile(`(?m)^\s*\{A(LEAVE[WLQ]|PUSHA[WL]|POPA[WL]|PUSHF[WLQ]|POPF[WLQ]),\s*ynone,\s*(P32|Py|Pe),`).FindAllStringSubmatch(string(data), -1)
	got := make(map[string]string)
	for _, row := range rows {
		if _, duplicate := got[row[1]]; duplicate {
			t.Fatalf("duplicate original zero-operand table row: %q", row[0])
		}
		got[row[1]] = row[2]
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("complete original ynone family differs: got %v, want %v", got, want)
	}
	for _, arch := range []string{"amd64", "386"} {
		for _, opcode := range []string{"LEAVEW", "LEAVEL", "LEAVEQ", "PUSHAW", "PUSHAL", "POPAW", "POPAL", "PUSHFW", "PUSHFL", "PUSHFQ", "POPFW", "POPFL", "POPFQ"} {
			t.Run(arch+"_"+opcode, func(t *testing.T) {
				source, object := oracleFixture(t)
				text := "TEXT probe(SB),$0-0\n\t" + opcode + "\n"
				if strings.HasPrefix(opcode, "PUSHF") {
					text += "\tPOPF" + strings.TrimPrefix(opcode, "PUSHF") + "\n"
				} else if strings.HasPrefix(opcode, "POPF") {
					text += "\tPUSHF" + strings.TrimPrefix(opcode, "POPF") + "\n"
				}
				text += "\tRET\n"
				if err := os.WriteFile(source, []byte(text), 0600); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				observed, err := goasmcmd.Observe(ctx, filepath.Dir(source),
					append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH="+arch),
					"go", "tool", "asm", "-o", object, source)
				encoded, _ := json.Marshal(observed)
				t.Logf("ORACLE_CHILD %s", encoded)
				accepted := !(arch == "amd64" && want[opcode] == "P32" || arch == "386" && want[opcode] == "Py")
				exit := 1
				if accepted {
					exit = 0
				}
				if observed.ExitCode != exit || !observed.Waited {
					t.Fatalf("actual original Go mode result differs: %+v %v", observed, err)
				}
				if !accepted {
					bits := 64
					if arch == "386" {
						bits = 32
					}
					if !strings.Contains(string(observed.Stderr), fmt.Sprintf("asm: asmins: illegal in %d-bit mode:", bits)) ||
						!strings.Contains(string(observed.Stderr), "("+source+":2)") {
						t.Fatalf("no exact original mode listing: %+v", observed)
					}
				}
				if failure := CheckOutcome(source, object, observed.Stdout, observed.Stderr, err,
					ctx.Err(), accepted, 2, nil); failure != nil {
					t.Fatalf("actual zero-operand source observation lost: %v", failure)
				}
				if !accepted {
					for _, control := range []struct {
						name           string
						stdout, stderr []byte
						cause          error
						context        error
					}{
						{"foreign", nil, []byte(strings.ReplaceAll(string(observed.Stderr), "("+source+":2)", "(foreign"+source+":2)")), err, nil},
						{"wrong-focus", nil, []byte(strings.ReplaceAll(string(observed.Stderr), "("+source+":2)", "("+source+":3)")), err, nil},
						{"footer", nil, []byte("asm: assembly failed\n"), err, nil},
						{"split-backend", []byte("asm: asmins: illegal in 64-bit mode:\n"), []byte("00000 (" + source + ":2) " + opcode + "\n"), err, nil},
						{"joined-cleanup", observed.Stdout, observed.Stderr, errors.Join(err, errors.New("cleanup failed")), nil},
						{"deadline", observed.Stdout, observed.Stderr, err, context.DeadlineExceeded},
						{"panic", observed.Stdout, append(append([]byte(nil), observed.Stderr...), []byte("panic: assembler defect\n")...), err, nil},
					} {
						if CheckOutcome(source, object, control.stdout, control.stderr, control.cause,
							control.context, false, 2, nil) == nil {
							t.Fatalf("%s acquired a source rejection role", control.name)
						}
					}
				}
			})
		}
	}
}

func TestDiagnosticZeroOperandCompleteStatementBinding(t *testing.T) {
	for _, test := range []struct {
		name, statement, listing string
		want                     bool
	}{
		{"zero", "LEAVEL", "LEAVEL", true},
		{"zero-whitespace", "\tLEAVEL  ", "  LEAVEL  ", true},
		{"line-comment", "LEAVEL // source comment", "LEAVEL", true},
		{"block-comment", "LEAVEL /* source comment */", "LEAVEL", true},
		{"suffix", "LEAVEQ.P", "LEAVEQ.P", true},
		{"wrong-opcode", "LEAVEL", "LEAVEQ", false},
		{"wrong-case", "LEAVEL", "leavel", false},
		{"wrong-suffix", "LEAVEQ.P", "LEAVEQ", false},
		{"truncated-registers", "MOVQ AX,BX", "MOVQ", false},
		{"truncated-unary", "PUSHQ AX", "PUSHQ", false},
		{"truncated-memory", "LEAVEW (AX)", "LEAVEW", false},
		{"truncated-commented-operand", "MOVQ /* comment */ AX,BX", "MOVQ", false},
		{"truncated-suffixed-operand", "MOVQ.P AX,BX", "MOVQ.P", false},
		{"truncated-expression", "MOVQ $1+2,AX", "MOVQ", false},
		{"truncated-empty-operand", "MOVQ ,", "MOVQ", false},
		{"second-statement", "LEAVEL; RET", "LEAVEL", false},
		{"operand-bearing-control", "MOVQ AX,BX", "MOVQ AX,BX", true},
		{"label-only", "LEAVEL:", "LEAVEL", false},
		{"label-prefix", "label: LEAVEL", "LEAVEL", false},
		{"comment-only", "/* LEAVEL */", "LEAVEL", false},
		{"malformed-comment", "LEAVEL /*", "LEAVEL", false},
		{"no-opcode", "", "LEAVEL", false},
		{"no-listing", "LEAVEL", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			source, _ := oracleFixture(t)
			data := "TEXT probe(SB),$0-0\n" + test.statement + "\nRET\n"
			if err := os.WriteFile(source, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			if got := ListingBindsSource(source, "2", "00018", test.listing); got != test.want {
				t.Fatalf("full source statement/listing bind=%t, want %t", got, test.want)
			}
			output := "asm: asmins: illegal in 32-bit mode: 00018 (" + source + ":2)\t" + test.listing + "\n"
			if got := SourceDiagnosticLine(source, output, 2); got != test.want {
				t.Fatalf("full diagnostic bind=%t, want %t", got, test.want)
			}
			for _, pc := range []string{"", "0", "0018", "000018", "-0018", "+0018", "0x012", "18446744073709551616"} {
				if ListingBindsSource(source, "2", pc, test.listing) {
					t.Fatalf("noncanonical listing PC acquired a role: %q", pc)
				}
			}
			for _, position := range []string{"0", "-2", "02", "9999"} {
				if ListingBindsSource(source, position, "00018", test.listing) {
					t.Fatalf("noncanonical/foreign source line acquired a role: %q", position)
				}
			}
		})
	}
}
