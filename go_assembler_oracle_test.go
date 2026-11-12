package plan9asm

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/internal/goasmoracle"
)

func goAssemblerOracleOutput(t *testing.T, arch, source, experiment string, wantSuccess bool) {
	t.Helper()
	dir := t.TempDir()
	asm, object := filepath.Join(dir, "forms.s"), filepath.Join(dir, "forms.o")
	if err := os.WriteFile(asm, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	stage, cancelStage := runtimeOracleStageContext(t)
	defer cancelStage()
	ctx, cancel := context.WithTimeout(stage, time.Minute)
	defer cancel()
	// Includes belong to the selected SDK, not the temporary source directory
	// or an ambient installation. Preserve source literals such as NOSPLIT.
	include := filepath.Join(runtime.GOROOT(), "pkg", "include")
	command := exec.CommandContext(ctx, "go", "tool", "asm", "-I", include, "-p", "example.com/forms", "-o", object, asm)
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH="+arch)
	if experiment != "" {
		command.Env = append(command.Env, "GOEXPERIMENT="+experiment)
	}
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if failure := goAssemblerOracleOutcome(asm, object, output, err, ctx.Err(), wantSuccess, arch, "example.com/forms"); failure != nil {
		t.Fatalf("%v\n%s\noriginal source:\n%s", failure, output, source)
	}
}

func goAssemblerOracleOutcome(source, object string, output []byte, commandErr, contextErr error, wantSuccess bool, arch string, packagePrefix ...string) error {
	return goasmoracle.CheckOutcome(source, object, output, nil, commandErr, contextErr,
		wantSuccess, 0, func(source, diagnostic string) bool {
			return arch == "wasm" && goasmoracle.WasmSourceDiagnosticLine(source, diagnostic, 0) ||
				goAssemblerOracleX86SourceDiagnostic(source, arch, diagnostic) ||
				goAssemblerOracleARM64SourceDiagnostic(source, arch, diagnostic) ||
				goAssemblerOraclePositionlessDiagnostic(source, arch, diagnostic) ||
				len(packagePrefix) == 1 && goAssemblerOracleX86ObservedPackageDiagnostic(source, arch, diagnostic, packagePrefix[0])
		})
}

func goAssemblerOracleSourceDiagnostic(source, output string) bool {
	return goasmoracle.SourceDiagnostic(source, output)
}

func TestGoAssemblerOracleActualCommonForms(t *testing.T) {
	for _, arch := range []string{"arm64", "amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			// These common forms deliberately invoke every actual compatibility
			// assembler, unlike a current-table oracle on an older toolchain.
			goAssemblerOracleOutput(t, arch, "TEXT ·valid(SB),$0-0\n\tRET\n", "", true)
			goAssemblerOracleOutput(t, arch, "TEXT ·invalid(SB),$0-0\n\tNOT_AN_INSTRUCTION\n\tRET\n", "", false)
			invalid := "MOVD (R0),RSP"
			if arch == "amd64" {
				invalid = "MOVQ (AX),(BX)"
			} else if arch == "386" {
				invalid = "MOVL (AX),(BX)"
			}
			goAssemblerOracleOutput(t, arch, "TEXT ·invalid(SB),$0-0\n\t"+invalid+"\n\tRET\n", "", false)
		})
	}
}

func TestGoAssemblerOracleOutcomeRejectsUnboundRejections(t *testing.T) {
	dir := t.TempDir()
	source, object := filepath.Join(dir, "forms.s"), filepath.Join(dir, "forms.o")
	if err := os.WriteFile(source, []byte("TEXT ·invalid(SB),$0-0\n\tNOT_AN_INSTRUCTION\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "tool", "asm", "-o", object, source)
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH=arm64")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if failure := goAssemblerOracleOutcome(source, object, output, err, ctx.Err(), false, "arm64"); failure != nil {
		t.Fatalf("actual source rejection lost: %v\n%s", failure, output)
	}
	for _, test := range []struct {
		name    string
		output  string
		err     error
		context error
	}{
		{name: "no diagnostic", err: err},
		{name: "footer only", output: "asm: assembly failed\n", err: err},
		{name: "foreign source", output: "other.s:2: bad operand\n", err: err},
		{name: "zero line", output: source + ":0: bad operand\n", err: err},
		{name: "negative line", output: source + ":-2: bad operand\n", err: err},
		{name: "overflow line", output: source + ":999999999999999999999999999999: bad operand\n", err: err},
		{name: "zero column", output: source + ":2:0: bad operand\n", err: err},
		{name: "negative column", output: source + ":2:-1: bad operand\n", err: err},
		{name: "empty column", output: source + ":2:: bad operand\n", err: err},
		{name: "empty message", output: source + ":2: \n", err: err},
		{name: "joined cleanup", output: string(output), err: errors.Join(err, errors.New("owned cleanup failure"))},
		{name: "canceled", output: string(output), err: err, context: context.Canceled},
		{name: "deadline", output: string(output), err: err, context: context.DeadlineExceeded},
		{name: "late infrastructure", output: string(output) + "fatal error: out of memory\n", err: err},
		{name: "panic with source diagnostic", output: string(output) + "panic: internal assembler failure\n", err: err},
	} {
		t.Run(test.name, func(t *testing.T) {
			failure := goAssemblerOracleOutcome(source, object, []byte(test.output), test.err, test.context, false, "arm64")
			if failure == nil || !strings.Contains(failure.Error(), "infrastructure failure") {
				t.Fatalf("unbound rejection accepted: %v", failure)
			}
		})
	}
}
