package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// These are required native execution axes. Darwin/Rosetta and QEMU numerical
// observations do not establish native Linux arithmetic or atomic semantics.
func TestCrossLinuxRuntimeMatrixX86LockScalarRMWNativeAMD64(t *testing.T) {
	x87IA32RequireNativeHost(t)
	TestCrossLinuxRuntimeMatrixX86LockScalarRMWOriginalAndLLVM(t)
	x87IA32RequireNativeHost(t)
}

func TestCrossLinuxRuntimeMatrixX86LockScalarRMWNative386(t *testing.T) {
	x87IA32RequireNativeHost(t)
	llc := findLLVM22Tool("llc")
	compiler, err := exec.LookPath("i686-linux-gnu-gcc")
	if llc == "" || err != nil {
		t.Fatal("required LLVM22 and IA32 static compiler unavailable", err)
	}
	declarations, assembly, driver, reference, count := x86LockScalarRuntimeFixture("386")
	if count != 129 {
		t.Fatal("complete IA32 kernel denominator changed", count)
	}
	want := fmt.Sprintf("lock observations %d\n", count*292*2*8)
	dir := t.TempDir()
	original := x86OrderingHintBuildOriginal(t, dir, "linux", "386", declarations, assembly, driver)
	sealed, err := x87IA32StaticExecutable(original)
	if err != nil {
		t.Fatal(err)
	}
	if output := x87IA32RunDirect(t, sealed, nil, os.Environ()); string(output) != want {
		t.Fatalf("actual original Go native IA32 full arithmetic/status/canary oracle: %q", output)
	}
	mode := "i386-unknown-linux-gnu"
	ir, err := x86OrderingHintTranslateAPI(t, "Go", assembly, declarations, "386", mode)
	if err != nil {
		t.Fatal(err)
	}
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			input := filepath.Join(dir, "lock"+level+".ll")
			object := filepath.Join(dir, "lock"+level+".o")
			main := filepath.Join(dir, "main.c")
			executable := filepath.Join(dir, "lock"+level)
			for name, contents := range map[string]string{input: ir, main: reference} {
				if err := os.WriteFile(name, []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
			}
			x86FloatCompareCaptureCommand(t, exec.Command(llc, level,
				"-mtriple="+mode, "-filetype=obj", input, "-o", object))
			x86FloatCompareCaptureCommand(t, exec.Command(compiler, "-static", "-no-pie",
				object, main, "-O2", "-o", executable))
			sealed, err := x87IA32StaticExecutable(executable)
			if err != nil {
				t.Fatal(err)
			}
			if output := x87IA32RunDirect(t, sealed, nil, os.Environ()); string(output) != want {
				t.Fatalf("native LLVM IA32 full-width/flags/MXCSR/canary oracle: %q", output)
			}
		})
	}
	x87IA32RequireNativeHost(t)
}
