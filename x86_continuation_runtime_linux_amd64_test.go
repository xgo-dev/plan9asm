//go:build linux && amd64

package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A required native owner, not a host-dependent optional axis. i386 executes
// through the same Linux AMD64 kernel compatibility ISA as the other native
// 386 owners. Missing LLVM22/static compiler/execution support fails outright.
func TestCrossLinuxRuntimeMatrixX86ContinuationWholeCFGOriginalGoAndLLVM(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	i386, err := exec.LookPath("i686-linux-gnu-gcc")
	if !found || err != nil {
		t.Fatalf("continuation native owner requires LLVM22 llc/clang and static i386 compiler: %v", err)
	}
	for _, arch := range []string{"amd64", "386"} {
		dispatches := []string{"memory", "register"}
		if arch == "386" {
			dispatches = append(dispatches, "BP-memory", "BP-register", "BP-target")
		}
		for _, dispatch := range dispatches {
			t.Run(arch+"/"+dispatch, func(t *testing.T) {
				mode := strings.TrimPrefix(dispatch, "BP-")
				if dispatch == "BP-target" {
					mode = "register"
				}
				source, options, goDriver, cDriver := x86ContinuationRuntimeFixture(t, arch, mode)
				if dispatch == "BP-target" {
					source = strings.ReplaceAll(source, "AX", "BP")
				} else if strings.HasPrefix(dispatch, "BP-") {
					source = strings.ReplaceAll(source, "SI", "BP")
				}
				compiler := []string{clang, "-target", options.TargetTriple, "-no-pie"}
				if arch == "386" {
					compiler = []string{i386, "-static", "-no-pie"}
				}
				execution := x86FloatCompareExecution{llc: llc, triple: options.TargetTriple, compiler: compiler}
				dir := t.TempDir()
				for name, contents := range map[string]string{
					"go.mod": "module continuationoracle\n\ngo 1.20\n", "main.go": goDriver,
					"continuation_" + arch + ".s": strings.ReplaceAll(source, "(SB),$0-", "(SB),4,$0-"),
				} {
					if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
						t.Fatal(err)
					}
				}
				original := filepath.Join(dir, "original")
				command := exec.Command("go", "build", "-p=1", "-o", original, ".")
				command.Dir = dir
				command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0", "GOMAXPROCS=2")
				x86FloatCompareCaptureCommand(t, command)
				want := "continuation original/LLVM: 7 independent checks\n"
				if output := execution.run(t, original); string(output) != want {
					t.Fatalf("incomplete original Go execution: %s", output)
				}
				for _, api := range []string{"text", "module", "owned-module"} {
					ir, err := x86ContinuationResultAPI(t, source, options, api)
					if err != nil {
						t.Fatal(api, err)
					}
					for _, optimized := range []bool{false, true} {
						input := ir
						if optimized {
							input = x86UndefinedTrapOptimizedIR(t, input)
						}
						for _, level := range []string{"-O0", "-O2"} {
							output := execution.compileAndRunLLVM(t, "continuation", input, cDriver, level)
							if string(output) != want {
								t.Fatalf("%s IR_O2=%t %s incomplete LLVM execution: %s", api, optimized, level, output)
							}
							t.Log(api, optimized, level, strings.TrimSpace(string(output)))
						}
					}
				}
			})
		}
	}
}
