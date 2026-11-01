package plan9asm

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// PUSHW's Pe row classifies this as Yi32 but calls vaddr without a relocation
// sink. This observes that backend defect, not an invalid source form or a
// successful Go object. The ordinary rejection oracle must not accept it.
func TestX86StackNamedAddressRelocationSinkDefect(t *testing.T) {
	const original = "TEXT ·Value(SB),4,$0-0\nPUSHW $other·cell(SB)\nPOPW AX\nRET\n"
	dir := t.TempDir()
	source, object := filepath.Join(dir, "forms.s"), filepath.Join(dir, "forms.o")
	if err := os.WriteFile(source, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	stage, cancelStage := runtimeOracleStageContext(t)
	defer cancelStage()
	ctx, cancel := context.WithTimeout(stage, time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin/go"), "tool", "asm",
		"-p", "example.com/forms", "-o", object, source)
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=386", "GOTOOLCHAIN=local")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	exit, ok := err.(*exec.ExitError)
	const diagnostic = "asm: need reloc for $other.cell(SB)\nasm: reloc\n"
	if ctx.Err() != nil || !ok || exit.ProcessState == nil || !exit.ProcessState.Exited() ||
		exit.ExitCode() != 1 || string(output) != diagnostic {
		t.Fatalf("unknown PUSHW backend observation: %v; context %v\n%s", err, ctx.Err(), output)
	}
	if goAssemblerOracleOutcome(source, object, output, err, ctx.Err(), false, "386") == nil {
		t.Fatal("relocation emitter defect became a source-rejection certificate")
	}
	if data, err := os.ReadFile(source); err != nil || string(data) != original {
		t.Fatal("backend observation lost its original source", err)
	}
	t.Log("GO_ASSEMBLER_DEFECT_OBSERVATION: PUSHW missing relocation sink; not Go form-rejection or object-compilation evidence")
}
