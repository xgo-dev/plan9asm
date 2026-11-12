package plan9asm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestX86InsertExtractActualSDKTablesAreMandatory(t *testing.T) {
	const rootName = "TestX86InsertExtractEveryGoOpcodeAttribute"
	for _, name := range []string{"avx_optabs.go", "asm6.go"} {
		t.Run(name, func(t *testing.T) {
			// Execute the actual attribute root from this SDK's test binary.
			// A partial fixture GOROOT supplies no replacement encoder evidence.
			fixture := t.TempDir()
			directory := filepath.Join(fixture, "src", "cmd", "internal", "obj", "x86")
			if err := os.MkdirAll(directory, 0700); err != nil {
				t.Fatal(err)
			}
			if name == "asm6.go" {
				original, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", "cmd", "internal", "obj", "x86", "avx_optabs.go"))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(directory, "avx_optabs.go"), original, 0600); err != nil {
					t.Fatal(err)
				}
			}
			missing := filepath.Join(directory, name)
			if _, err := os.ReadFile(missing); !os.IsNotExist(err) {
				t.Fatalf("missing-table fixture is not absent: %v", err)
			}

			stage, cancelStage := runtimeOracleStageContext(t)
			defer cancelStage()
			ctx, cancel := context.WithTimeout(stage, 30*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+rootName+"$", "-test.count=1", "-test.timeout=20s")
			for _, item := range os.Environ() {
				if !strings.HasPrefix(item, "GOROOT=") {
					command.Env = append(command.Env, item)
				}
			}
			command.Env = append(command.Env, "GOROOT="+fixture)
			output, err := runtimeOracleCombinedOutput(ctx, command)
			exit, plainExit := err.(*exec.ExitError)
			if ctx.Err() != nil || !plainExit || exit.ProcessState == nil ||
				!exit.ProcessState.Exited() || exit.ExitCode() != 1 {
				t.Fatalf("actual SDK-table root did not fail with plain exit 1: %v (context %v)\n%s", err, ctx.Err(), output)
			}

			// Bind the complete failure to this one root, its real source file,
			// and the exact missing table. Panics, cleanup errors, extra failures,
			// unrelated diagnostics and a PASS from version-return are not evidence.
			_, missingErr := os.ReadFile(missing)
			if !os.IsNotExist(missingErr) {
				t.Fatalf("missing-table fixture changed during the child: %v", missingErr)
			}
			if !x86InsertExtractMissingTableOutput(output, rootName, missingErr.Error(), testing.CoverMode() != "") {
				t.Fatalf("unbound actual SDK-table failure (want %s):\n%s", missing, output)
			}
			t.Logf("actual %s child: plain exit 1, exact %s diagnostic\n%s", runtime.Version(), name, output)
		})
	}
}

func x86InsertExtractMissingTableOutput(output []byte, root, diagnostic string, covered bool) bool {
	pattern := fmt.Sprintf(`\A--- FAIL: %s \([0-9]+\.[0-9]+s\)\n    amd64_insert_extract_forms_test\.go:[0-9]+: %s\nFAIL\n`,
		regexp.QuoteMeta(root), regexp.QuoteMeta(diagnostic))
	if covered {
		// The child is this same instrumented test binary. Require Go's one
		// coverage trailer only in that role; never strip arbitrary output.
		// Go 1.20's coverage writer also prints this exact package prefix.
		pattern += `(?:\tgithub\.com/xgo-dev/plan9asm\t)?coverage: (?:(?:[0-9]|[1-9][0-9])\.[0-9]|100\.0)% of statements\n`
	}
	return regexp.MustCompile(pattern + `\z`).Match(output)
}

func TestX86InsertExtractMissingTableOutputGrammar(t *testing.T) {
	const root, diagnostic = "TestActualTable", "open exact/asm6.go: missing table"
	base := "--- FAIL: " + root + " (0.01s)\n    amd64_insert_extract_forms_test.go:66: " + diagnostic + "\nFAIL\n"
	const trailer = "coverage: 0.2% of statements\n"
	for _, covered := range []bool{false, true} {
		valid := base
		if covered {
			valid += trailer
		}
		if !x86InsertExtractMissingTableOutput([]byte(valid), root, diagnostic, covered) {
			t.Fatalf("exact original failure rejected (coverage=%v)", covered)
		}
		for _, invalid := range []string{
			valid + "PASS\n", "panic: unrelated\n" + valid, valid + trailer,
			strings.Replace(valid, "exact/asm6.go", "other/asm6.go", 1),
			strings.Replace(valid, root, "TestAnotherRoot", 1),
		} {
			if x86InsertExtractMissingTableOutput([]byte(invalid), root, diagnostic, covered) {
				t.Fatalf("unbound child failure accepted (coverage=%v): %q", covered, invalid)
			}
		}
	}
	if x86InsertExtractMissingTableOutput([]byte(base), root, diagnostic, true) ||
		x86InsertExtractMissingTableOutput([]byte(base+trailer), root, diagnostic, false) {
		t.Fatal("child borrowed the wrong coverage instrumentation role")
	}
	if !x86InsertExtractMissingTableOutput([]byte(base+"\tgithub.com/xgo-dev/plan9asm\t"+trailer), root, diagnostic, true) ||
		x86InsertExtractMissingTableOutput([]byte(base+"\tother/package\t"+trailer), root, diagnostic, true) {
		t.Fatal("historical coverage trailer lost its exact package identity")
	}
}
