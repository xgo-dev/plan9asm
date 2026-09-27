package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// requireX86GoAssemblerResult keeps the Go 1.27 table oracle available to
// tests that must remain visible to llgo. Older compatibility toolchains still
// exercise parsing, translation, and LLVM compilation, but cannot define the
// current operand grammar.
func requireX86GoAssemblerResult(t *testing.T, goarch, src string, wantSuccess bool) {
	t.Helper()
	if !goToolchainAtLeast(runtime.Version(), 1, 27) {
		return
	}
	dir := t.TempDir()
	asm := filepath.Join(dir, "forms.s")
	if err := os.WriteFile(asm, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "tool", "asm", "-p", "example.com/forms", "-o", filepath.Join(dir, "forms.o"), asm)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch)
	out, err := cmd.CombinedOutput()
	if wantSuccess && err != nil {
		t.Fatalf("Go 1.27 %s assembler rejected accepted forms: %v\n%s", goarch, err, out)
	}
	if !wantSuccess && err == nil {
		t.Fatalf("Go 1.27 %s assembler accepted a form expected outside the optab:\n%s", goarch, src)
	}
}
