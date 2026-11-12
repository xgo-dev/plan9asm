//go:build unix

package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Every host compiles the actual Go-byte original/LLVM oracle. Only the required
// Linux/amd64 runtime root executes it; this test is not native ISA evidence.
func TestX86PackedMoveAlignedOriginalGoOracleCompileOnly(t *testing.T) {
	execution := fixedLocalPackedCompileOnlyTools(t)
	ir, main, count := x86PackedMoveObservableFixture(t, true, true, execution.triple)
	compileLLVMToObject(t, execution.llc, execution.triple, "aligned-oracle.ll", "aligned-oracle.o", ir)
	dir := t.TempDir()
	source, object := filepath.Join(dir, "oracle.c"), filepath.Join(dir, "oracle.o")
	if err := os.WriteFile(source, []byte(main), 0600); err != nil {
		t.Fatal(err)
	}
	command := append([]string(nil), execution.compiler...)
	command = append(command, "-O2", "-c", source, "-o", object)
	x86FloatCompareCaptureCommand(t, exec.Command(command[0], command[1:]...))
	t.Logf("compiled %d original-Go aligned cases; native numerical/fault execution NOT performed by this test", count)
}
