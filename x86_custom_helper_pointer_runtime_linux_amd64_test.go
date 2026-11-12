//go:build linux && amd64

package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
)

// This new exhaustive owner does not add rows to the existing ABI0 bool-byte
// owner. Both original Go386 and LLVM ELF32 programs run directly through the
// native Linux AMD64 kernel; a missing native compatibility ISA fails.
func TestCrossLinuxRuntimeMatrixX86CustomHelperDistinctPointerRolesOriginalGoAndLLVM(t *testing.T) {
	x87IA32RequireNativeHost(t)
	llc := findLLVM22Tool("llc")
	compiler, err := exec.LookPath("i686-linux-gnu-gcc")
	if llc == "" || err != nil {
		t.Fatalf("required LLVM22/native i386 pointer-role tools: llc=%q compiler=%v", llc, err)
	}
	t.Logf("actual i386 compiler: %s", x86FloatCompareCaptureCommand(t, exec.Command(compiler, "--version")))
	execution := x86FloatCompareExecution{llc: llc, triple: "i386-unknown-linux-gnu",
		compiler: []string{compiler, "-static", "-no-pie"}}
	forms := x86CustomPointerRuntimeForms()
	for start := 0; start < len(forms); start += x86CustomPointerRuntimeBatchSize {
		t.Run(fmt.Sprintf("batch%02d", start/4), func(t *testing.T) {
			x86CustomPointerRuntimeBatch(t, execution, start)
		})
	}
	t.Log("16 complete custom386 pointer helpers: nine scalar load/extension forms and seven whole128 names; original Go logical/raw bool calls, independent numerical/byte oracles, full input and result canaries; three LLVM APIs/backend O0/O2. Not a C _Bool or SDK closure certificate.")
	x87IA32RequireNativeHost(t)
}

func x86CustomPointerRuntimeBatch(t *testing.T, execution x86FloatCompareExecution, start int) {
	t.Helper()
	assembly, declarations, _, _, helpers := x86CustomPointerRuntimeSource(t, start)
	_, driver, wrappers := x86CustomPointerRuntimeDrivers(t, start)
	original := x86CustomPointerRuntimeOriginal(t, start)
	originalProgram, err := x87IA32StaticExecutable(original)
	if err != nil {
		t.Fatal(err)
	}
	wantChecks := x86CustomPointerRuntimeChecks(start)
	wantOriginal := fmt.Sprintf("original386 pointer-role checks: %d\n", wantChecks)
	if output := x87IA32RunDirect(t, originalProgram, nil, os.Environ()); string(output) != wantOriginal {
		t.Fatalf("incomplete original Go386 pointer-role batch: %s", output)
	}
	pkg := mustGoPackage(t, "pointerroles386", "package main\n"+declarations)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewPackageAPIWithManual(t, assembly, pkg, "386", execution.triple, api,
				func(name string) (FuncSig, bool) { sig, ok := helpers[name]; return sig, ok })
			if err != nil {
				t.Fatal(err)
			}
			for _, level := range []string{"-O0", "-O2"} {
				t.Run(level, func(t *testing.T) {
					executable := execution.compileLLVM(t, "custom-pointer-386", ir+wrappers, driver, level)
					translatedProgram, err := x87IA32StaticExecutable(executable)
					if err != nil {
						t.Fatal(err)
					}
					want := fmt.Sprintf("LLVM386 pointer-role checks: %d\n", wantChecks)
					if output := x87IA32RunDirect(t, translatedProgram, nil, os.Environ()); string(output) != want {
						t.Fatalf("incomplete independent LLVM pointer-role batch: %s", output)
					}
				})
			}
		})
	}
}
