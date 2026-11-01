package plan9asm

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Keep the complete historical source bodies and all 33/24 accepted operands.
// The official include changes no instruction: it supplies their original
// NOSPLIT/NOPTR spellings from the selected actual SDK, not a invented ABI.
func x86CMPXCHGMixedOriginalCatalogue(t *testing.T, arch, source string) {
	t.Helper()
	directory := t.TempDir()
	input, object := filepath.Join(directory, "complete.s"), filepath.Join(directory, "complete.o")
	if err := os.WriteFile(input, []byte("#include \"textflag.h\"\n"+source), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), "tool", "asm", "-S",
		"-I", filepath.Join(runtime.GOROOT(), "pkg", "include"), "-p", "ordering", "-o", object, input)
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH="+arch,
		"GOFLAGS=", "GOENV=off", "GOWORK=off", "GOEXPERIMENT=")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if failure := goAssemblerOracleOutcome(input, object, output, err, ctx.Err(), true, arch); failure != nil {
		t.Fatalf("actual complete original syntax object: %v\n%s", failure, output)
	}
	t.Logf("actual original complete accepted catalogue, not unsafe execution:\n%s", output)
	file, err := Parse(ArchAMD64, source)
	if err != nil || len(file.Funcs) != 1 {
		t.Fatalf("complete original source parse: %v", err)
	}
	count, physicalContext := 0, 0
	for _, instruction := range file.Funcs[0].Instrs {
		if !strings.HasPrefix(string(instruction.Op), "CMPXCHG") {
			continue
		}
		_, recognized, err := x86CompareExchangeProperties(instruction.Op, instruction, arch)
		if !recognized || err != nil && !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("actual original accepted row disappeared from grammar: %+v/%v", instruction, err)
		}
		count++
		if err != nil {
			physicalContext++
			t.Logf("source/physical bank or native #UD Context: %s: %v", instruction.Raw, err)
		}
	}
	want := 33
	if arch == "386" {
		want = 24
	}
	if count != want || physicalContext != 5 {
		t.Fatalf("complete original syntax/physical-context denominator changed: %d/%d, want %d/5", count, physicalContext, want)
	}
}
