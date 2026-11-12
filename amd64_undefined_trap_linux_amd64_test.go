package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Required Linux counterpart: real IA32 instructions, a sealed static ELF32
// executable, no emulator or host-inapplicable skip.
func TestCrossLinuxRuntimeMatrixX86UndefinedTrapNative386(t *testing.T) {
	x87IA32RequireNativeHost(t)
	llc := findLLVM22Tool("llc")
	compiler, err := exec.LookPath("i686-linux-gnu-gcc")
	if llc == "" || err != nil {
		t.Fatalf("required LLVM 22 llc/native IA32 compiler: %v", err)
	}
	for _, raw := range []bool{false, true} {
		t.Run(fmt.Sprintf("raw=%t", raw), func(t *testing.T) {
			original := x86UndefinedTrapBuildOriginal(t, "linux", "386", raw)
			sealed, err := x87IA32StaticExecutable(original)
			if err != nil || sealed.verify() != nil {
				t.Fatalf("unsealed original IA32 undefined-instruction executable: %v", err)
			}
			output, err := x87IA32Capture(t, sealed.path, nil, "", append(os.Environ(), "GOTRACEBACK=system"))
			if guard := sealed.verify(); guard != nil {
				t.Fatal(guard)
			}
			x86UndefinedTrapRequireOriginalSignal(t, output, err)
			ir := x86UndefinedTrapIR(t, x86UndefinedTrapFixture(raw), "386", "i386-unknown-linux-gnu", "Go")
			for _, level := range []string{"-O0", "-O2"} {
				t.Run(level, func(t *testing.T) {
					optimized := ir
					if level == "-O2" {
						optimized = x86UndefinedTrapOptimizedIR(t, ir)
					}
					dir := t.TempDir()
					input, object := filepath.Join(dir, "undefined.ll"), filepath.Join(dir, "undefined.o")
					main, executable := filepath.Join(dir, "main.c"), filepath.Join(dir, "undefined")
					for name, contents := range map[string]string{input: optimized, main: x86UndefinedTrapIndependentC} {
						if err := os.WriteFile(name, []byte(contents), 0600); err != nil {
							t.Fatal(err)
						}
					}
					x86FloatCompareCaptureCommand(t, exec.Command(llc, level, "-mtriple=i386-unknown-linux-gnu",
						"-filetype=obj", input, "-o", object))
					x86FloatCompareCaptureCommand(t, exec.Command(compiler, "-static", "-no-pie", object, main, "-O2", "-o", executable))
					sealed, err := x87IA32StaticExecutable(executable)
					if err != nil {
						t.Fatal(err)
					}
					if output := x87IA32RunDirect(t, sealed, nil, os.Environ()); string(output) != "undefined-instruction SIGILL verified\n" {
						t.Fatalf("native IA32 LLVM fault identity: %q", output)
					}
				})
			}
		})
	}
	x87IA32RequireNativeHost(t)
}
