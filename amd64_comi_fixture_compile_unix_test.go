//go:build unix

package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Consume the exact builders used by all four native Linux owners without
// executing an AVX/AVX512 opcode. Linux objects, original Go linked programs
// and the host-target C attachment have separate, explicit compilation claims.
func TestX86COMINativeRuntimeFixturesCompileOnly(t *testing.T) {
	execution := fixedLocalPackedCompileOnlyTools(t)
	total := 0
	t.Run("RawNativeCompare", func(t *testing.T) {
		source, _, driver, count := x86COMIRawNativeFixture(t)
		var declarations strings.Builder
		for index := 0; index < count; index++ {
			fmt.Fprintf(&declarations, "func flagcompare%d(a,b,out *byte)\n", index)
		}
		if count != 24 {
			t.Fatal("raw complete runtime inventory changed", count)
		}
		x86COMICompileFixture(t, execution, source, declarations.String(), driver)
		total += count
	})
	t.Run("NativeDeadExceptions", func(t *testing.T) {
		source, declarations, driver, count, traps := x86COMIDeadFaultFixture(t, true, execution.triple)
		if count != 12 || traps != 1 {
			t.Fatal("native exception checks dropped", count, traps)
		}
		x86COMICompileFixture(t, execution, source, declarations, driver)
		total += count
	})
	for _, axis := range []x86FloatCompareRuntimeISA{x86FloatCompareVEX, x86FloatCompareEVEX} {
		t.Run(fmt.Sprintf("NativeVectorFlags/ISA%d", axis), func(t *testing.T) {
			cases := x86ScalarCompareAFRuntimeCases(axis)
			if len(cases) != 48 {
				t.Fatal("native FLAGS inventory changed", len(cases))
			}
			files := x86ScalarCompareAFOriginalFiles(axis)
			x86COMICompileOriginalGo(t, files, true)
			declarations := strings.TrimPrefix(files["status.go"], "package scalarstatus\n")
			x86COMICompileFixture(t, execution, files["status_amd64.s"], declarations, x86ScalarCompareAFRuntimeC(cases))
			total += len(cases)
		})
		t.Run(fmt.Sprintf("NativeVectorMXCSR/ISA%d", axis), func(t *testing.T) {
			source, declarations, original, driver, count := x86COMIConstantOracle(axis)
			want := 24
			if axis == x86FloatCompareEVEX {
				want = 96
			}
			if count != want {
				t.Fatal("native MXCSR inventory changed", count, want)
			}
			x86COMICompileOriginalGo(t, map[string]string{
				"go.mod": "module comistatus\n\ngo 1.20\n", "main.go": original, "original_amd64.s": source,
			}, false)
			x86COMICompileFixture(t, execution, source, declarations, driver)
			total += count
		})
	}
	if total != 252 {
		t.Fatal("four native owner fixtures are not exhaustively compiled", total)
	}
	t.Log("252 exact native runtime kernels compiled in six bounded batches (at most 96 functions); no native AVX/AVX512 or trap execution performed")
}

func x86COMICompileOriginalGo(t *testing.T, files map[string]string, testPackage bool) {
	t.Helper()
	dir := t.TempDir()
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	arguments := []string{"build", "-p=2", "-o", filepath.Join(dir, "original"), "."}
	if testPackage {
		arguments = []string{"test", "-c", "-p=2", "-vet=off", "-o", filepath.Join(dir, "original"), "."}
	}
	goBinary, _ := x86LEAActualSDKDriver(t)
	command := exec.Command(goBinary, arguments...)
	command.Dir = dir
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOMAXPROCS=2")
	x86FloatCompareCaptureCommand(t, command)
}

func x86COMICompileFixture(t *testing.T, execution x86FloatCompareExecution, source, declarations, driver string) {
	t.Helper()
	goAssemblerOracleOutput(t, "amd64", source, "", true)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", "x86_64-unknown-linux-gnu", api)
			if err != nil {
				t.Fatal(err)
			}
			for _, optimized := range []bool{false, true} {
				t.Run(fmt.Sprintf("IR_O2=%v", optimized), func(t *testing.T) {
					input := ir
					if optimized {
						input = x86MulDivRoundOptimize(t, input)
					}
					compileLLVMToObject(t, execution.llc, "x86_64-unknown-linux-gnu", "comi.ll", "comi.o", input)
				})
			}
		})
	}
	// Link (but never run) the same actual C/native-byte oracle on the available
	// host ABI. On non-Linux hosts this is not Linux libc/link/runtime evidence.
	ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", execution.triple, "text")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	input, object := filepath.Join(dir, "comi.ll"), filepath.Join(dir, "comi.o")
	csource, executable := filepath.Join(dir, "oracle.c"), filepath.Join(dir, "oracle")
	for path, contents := range map[string]string{input: x86MulDivRoundOptimize(t, ir), csource: driver} {
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	x86FloatCompareCaptureCommand(t, exec.Command(execution.llc, "-O2", "-mtriple="+execution.triple, "-filetype=obj", input, "-o", object))
	command := append([]string(nil), execution.compiler...)
	command = append(command, "-O2", csource, object, "-lm", "-o", executable)
	x86FloatCompareCaptureCommand(t, exec.Command(command[0], command[1:]...))
}
