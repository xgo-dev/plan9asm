package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86UnlockedScalarRMWNativeAMD64(t *testing.T) {
	x87IA32RequireNativeHost(t)
	execution := x86FloatCompareExecutionTools(t)
	declarations, source, driver, reference, count := x86UnlockedScalarRMWRuntimeFixture("amd64", true)
	if count != 156 {
		t.Fatal("complete ordinary AMD64 kernel denominator changed", count)
	}
	want := fmt.Sprintf("unlocked observations %d\n", count*292*2*8)
	original := x86OrderingHintBuildOriginal(t, t.TempDir(), "linux", "amd64", declarations, source, driver)
	if output := execution.run(t, original); string(output) != want {
		t.Fatalf("actual original Go ordinary memory/FLAGS/MXCSR/canary oracle: %q", output)
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86OrderingHintTranslateAPI(t, api, source, declarations, "amd64", execution.triple)
			if err != nil {
				t.Fatal(err)
			}
			for _, level := range []string{"-O0", "-O2"} {
				if output := execution.compileAndRunLLVM(t, "ordinary-rmw", ir, reference, level); string(output) != want {
					t.Fatalf("native LLVM ordinary memory/FLAGS/MXCSR/canary oracle: %q", output)
				}
			}
		})
	}
	x87IA32RequireNativeHost(t)
}

func TestCrossLinuxRuntimeMatrixX86UnlockedScalarRMWNative386(t *testing.T) {
	x87IA32RequireNativeHost(t)
	llc := findLLVM22Tool("llc")
	compiler, err := exec.LookPath("i686-linux-gnu-gcc")
	if llc == "" || err != nil {
		t.Fatal("required LLVM22 and IA32 static compiler unavailable", err)
	}
	declarations, source, driver, reference, count := x86UnlockedScalarRMWRuntimeFixture("386", true)
	if count != 117 {
		t.Fatal("complete ordinary IA32 kernel denominator changed", count)
	}
	want := fmt.Sprintf("unlocked observations %d\n", count*292*2*8)
	directory := t.TempDir()
	original := x86OrderingHintBuildOriginal(t, directory, "linux", "386", declarations, source, driver)
	sealed, err := x87IA32StaticExecutable(original)
	if err != nil {
		t.Fatal(err)
	}
	if output := x87IA32RunDirect(t, sealed, nil, os.Environ()); string(output) != want {
		t.Fatalf("actual original Go ordinary IA32 full-width/status/canary oracle: %q", output)
	}
	triple := "i386-unknown-linux-gnu"
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86OrderingHintTranslateAPI(t, api, source, declarations, "386", triple)
			if err != nil {
				t.Fatal(err)
			}
			for _, level := range []string{"-O0", "-O2"} {
				input := filepath.Join(directory, api+level+".ll")
				object := filepath.Join(directory, api+level+".o")
				main := filepath.Join(directory, api+level+".c")
				executable := filepath.Join(directory, api+level)
				for name, contents := range map[string]string{input: ir, main: reference} {
					if err := os.WriteFile(name, []byte(contents), 0600); err != nil {
						t.Fatal(err)
					}
				}
				x86FloatCompareCaptureCommand(t, exec.Command(llc, level, "-mtriple="+triple,
					"-filetype=obj", input, "-o", object))
				x86FloatCompareCaptureCommand(t, exec.Command(compiler, "-static", "-no-pie",
					object, main, "-O2", "-o", executable))
				sealed, err := x87IA32StaticExecutable(executable)
				if err != nil {
					t.Fatal(err)
				}
				if output := x87IA32RunDirect(t, sealed, nil, os.Environ()); string(output) != want {
					t.Fatalf("native LLVM IA32 ordinary full-width/FLAGS/MXCSR/canary oracle: %q", output)
				}
			}
		})
	}
	x87IA32RequireNativeHost(t)
}
