//go:build linux && amd64

package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Other hosts compile the independent Go ELF and validate portable source
// controls. This default Linux owner executes the original and all three
// translated API paths; no host skip or artifact generation is execution.
func TestCrossLinuxRuntimeMatrixAMD64LinuxRawSyscall(t *testing.T) {
	if !t.Run("original-Go-kernel", TestX86LinuxSyscallOriginalGo) {
		t.Fatal("original Go kernel precondition failed")
	}
	llc, clang, found := findLlcAndClang(t)
	opt := findLLVM22Tool("opt")
	if !found || opt == "" {
		t.Fatal("Linux raw syscall runtime requires LLVM22 llc, opt and clang")
	}
	execution := x86FloatCompareExecution{llc: llc, triple: "x86_64-unknown-linux-gnu",
		compiler: []string{clang, "-target", "x86_64-unknown-linux-gnu"}}
	driver, err := os.ReadFile("testdata/amd64/linux-syscall/main.c")
	if err != nil {
		t.Fatal(err)
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, x86LinuxSyscallAssembly, x86LinuxSyscallDeclaration, "amd64", execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, level := range []int{0, 2} {
				t.Run(fmt.Sprintf("IR-O%d", level), func(t *testing.T) {
					directory := t.TempDir()
					input, output := filepath.Join(directory, "input.ll"), filepath.Join(directory, "optimized.ll")
					if err := os.WriteFile(input, []byte(ir), 0o600); err != nil {
						t.Fatal(err)
					}
					ctx, cancel := runtimeOracleStageContext(t)
					command := exec.CommandContext(ctx, opt, "-S", fmt.Sprintf("-passes=default<O%d>", level), input, "-o", output)
					messages, err := runtimeOracleCombinedOutput(ctx, command)
					cancel()
					if err != nil {
						t.Fatalf("LLVM22 optimization: %v\n%s", err, messages)
					}
					optimized, err := os.ReadFile(output)
					if err != nil {
						t.Fatal(err)
					}
					for _, backend := range []string{"-O0", "-O2"} {
						t.Run("backend"+backend, func(t *testing.T) {
							actual := execution.compileAndRunLLVM(t, "raw-syscall", string(optimized), string(driver), backend)
							if strings.TrimSpace(string(actual)) != "RAW_SYSCALL_REFERENCE calls=4 failures=0\nRAW_SYSCALL_TRANSLATED calls=4 failures=0" {
								t.Fatalf("incomplete kernel oracle outcomes: %s", actual)
							}
							t.Log("RAW_SYSCALL_KERNEL_PIPELINE_PASS", api, level, backend, strings.TrimSpace(string(actual)))
						})
					}
				})
			}
		})
	}
}
