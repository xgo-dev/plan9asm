package plan9asm

import (
	"debug/pe"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The Windows runtime oracle links with MSYS2/MinGW clang. Large generated
// functions must call its real stack-probing helper, not the MSVC CRT helper.
// Cross-compiling this fixture makes the regression visible on every host.
func TestRuntimeWindowsStackProbeMatchesMinGW(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	const source = `declare void @use_stack(ptr)
define void @stackprobe() {
  %stack = alloca [8192 x i8], align 16
  call void @use_stack(ptr %stack)
  ret void
}
`
	for _, tc := range []struct {
		name, triple, symbol string
	}{
		{"runtime-mingw", testTargetTriple("windows", "amd64"), "___chkstk_ms"},
		{"explicit-msvc", "x86_64-pc-windows-msvc", "__chkstk"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			input, output := filepath.Join(dir, "stack.ll"), filepath.Join(dir, "stack.obj")
			if err := os.WriteFile(input, []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command(llc, "-mtriple="+tc.triple, "-filetype=obj", input, "-o", output).CombinedOutput(); err != nil {
				t.Fatalf("LLVM 22 compile: %v\n%s", err, out)
			}
			object, err := pe.Open(output)
			if err != nil {
				t.Fatal(err)
			}
			defer object.Close()
			for _, symbol := range object.Symbols {
				if symbol.Name == tc.symbol && symbol.SectionNumber == 0 {
					return
				}
			}
			t.Fatalf("%s did not reference the required CRT stack probe %s", tc.triple, tc.symbol)
		})
	}
}
