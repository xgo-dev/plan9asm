package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Required Linux/amd64 CI runs the actual static ELF32 objects directly. The
// host/ELF checks reject emulation; no local Rosetta run establishes this axis.
func TestCrossLinuxRuntimeMatrixX86OrderingHintsNative386(t *testing.T) {
	declarations, assembly, driver, reference := x86OrderingHintRuntimeFixture(32)
	x86OrderingHintNative386(t, declarations, assembly, driver, reference)
}

func TestCrossLinuxRuntimeMatrixX86RawNOPNative386(t *testing.T) {
	declarations, assembly, driver, reference := x86RawNOPRuntimeFixture(32)
	x86OrderingHintNative386(t, declarations, assembly, driver, reference)
}

func TestCrossLinuxRuntimeMatrixX86RawNOPOriginalAMD64(t *testing.T) {
	x87IA32RequireNativeHost(t)
	declarations, assembly, driver, _ := x86RawNOPRuntimeFixture(64)
	original := x86OrderingHintBuildOriginal(t, t.TempDir(), "linux", "amd64", declarations, assembly, driver)
	if output := x86FloatCompareCaptureCommand(t, exec.Command(original)); string(output) != "original ordering observations 256\n" {
		t.Fatalf("actual original Go AMD64 NOP state/no-memory oracle: %q", output)
	}
	x87IA32RequireNativeHost(t)
}

func x86OrderingHintNative386(t *testing.T, declarations, assembly, driver, reference string) {
	t.Helper()
	x87IA32RequireNativeHost(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	compiler, err := exec.LookPath("i686-linux-gnu-gcc")
	if err != nil {
		t.Fatal("required native IA32 static C compiler:", err)
	}
	dir := t.TempDir()
	original := x86OrderingHintBuildOriginal(t, dir, "linux", "386", declarations, assembly, driver)
	sealed, err := x87IA32StaticExecutable(original)
	if err != nil {
		t.Fatal(err)
	}
	if output := x87IA32RunDirect(t, sealed, nil, os.Environ()); string(output) != "original ordering observations 256\n" {
		t.Fatalf("unchanged original Go IA32 ordering/status/canary oracle: %q", output)
	}
	ir, err := x86OrderingHintTranslateAPI(t, "Go", assembly, declarations, "386", "i386-unknown-linux-gnu")
	if err != nil {
		t.Fatal(err)
	}
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			input := filepath.Join(dir, "ordering"+level+".ll")
			object := filepath.Join(dir, "ordering"+level+".o")
			main, executable := filepath.Join(dir, "main.c"), filepath.Join(dir, "ordering"+level)
			for name, contents := range map[string]string{input: ir, main: reference} {
				if err := os.WriteFile(name, []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
			}
			x86FloatCompareCaptureCommand(t, exec.Command(llc, level,
				"-mtriple=i386-unknown-linux-gnu", "-filetype=obj", input, "-o", object))
			x86FloatCompareCaptureCommand(t, exec.Command(compiler, "-static", "-no-pie",
				object, main, "-O2", "-o", executable))
			sealed, err := x87IA32StaticExecutable(executable)
			if err != nil {
				t.Fatal(err)
			}
			if output := x87IA32RunDirect(t, sealed, nil, os.Environ()); string(output) != "ordering observations 256\n" {
				t.Fatalf("LLVM IA32 GP/six-status-flags/MXCSR/canary oracle: %q", output)
			}
		})
	}
	x87IA32RequireNativeHost(t)
}
