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

func TestCrossLinuxRuntimeMatrixX86Linux386RawSyscall(t *testing.T) {
	x87IA32RequireNativeHost(t)
	if !t.Run("original-Go", TestX86Linux386SyscallOriginalGo) {
		t.Fatal("original Go syscall fixture failed")
	}
	llc := findLLVM22Tool("llc")
	compiler, err := exec.LookPath("i686-linux-gnu-gcc")
	if llc == "" || err != nil {
		t.Fatalf("Linux/386 syscall requires LLVM22 llc and i686-linux-gnu-gcc: %v", err)
	}
	execution := x86FloatCompareExecution{llc: llc, triple: "i386-unknown-linux-gnu",
		compiler: []string{compiler, "-static", "-no-pie"}}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, x86Linux386SyscallAssembly, x86LinuxSyscallDeclaration, "386", execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			ir += x86Linux386SyscallResultAdapter
			for _, optimized := range []bool{false, true} {
				text := ir
				if optimized {
					text = x86DwordProductIROptimize(t, ir)
				}
				for _, level := range []string{"-O0", "-O2"} {
					t.Run(fmt.Sprintf("IR-O2=%t/backend%s", optimized, level), func(t *testing.T) {
						output := execution.compileAndRunLLVM(t, "raw-syscall-386", text, x86Linux386SyscallOracle, level)
						if strings.TrimSpace(string(output)) != "RAW_SYSCALL_386 calls=3 failures=0" {
							t.Fatalf("incomplete Linux/386 syscall oracle: %s", output)
						}
					})
				}
			}
		})
	}
}

// The translated pair uses LLVM's aggregate return. C sees explicit words.
const x86Linux386SyscallResultAdapter = `
define void @RawOut(ptr %out, i32 %n, i32 %a, i32 %b, i32 %c, i32 %d, i32 %e, i32 %f) {
  %pair = call { i32, i32 } @Raw(i32 %n, i32 %a, i32 %b, i32 %c, i32 %d, i32 %e, i32 %f)
  %ax = extractvalue { i32, i32 } %pair, 0
  %dx = extractvalue { i32, i32 } %pair, 1
  %second = getelementptr i32, ptr %out, i32 1
  store i32 %ax, ptr %out, align 4
  store i32 %dx, ptr %second, align 4
  ret void
}
`

const x86Linux386SyscallOracle = `
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

extern void RawOut(uint32_t *, uint32_t, uint32_t, uint32_t, uint32_t,
                   uint32_t, uint32_t, uint32_t);

int main(void) {
    uint32_t result[2];
    const uint32_t sentinel = UINT32_C(0xfedcba98);
    errno = EDOM;
    RawOut(result, SYS_getpid, 0, 0, sentinel, 0, 0, 0);
    if (result[0] != (uint32_t)getpid() || result[1] != sentinel || errno != EDOM) return 1;
    RawOut(result, UINT32_MAX, 0, 0, sentinel, 0, 0, 0);
    if (result[0] != (uint32_t)-ENOSYS || result[1] != sentinel || errno != EDOM) return 2;

    // A nonzero mmap2 page offset observes the sixth argument in BP.
    FILE *file = tmpfile();
    if (!file) return 3;
    int fd = fileno(file);
    if (ftruncate(fd, 8192) || pwrite(fd, "V", 1, 4096) != 1) return 4;
    RawOut(result, SYS_mmap2, 0, 4096, PROT_READ, MAP_PRIVATE, fd, 1);
    if (result[0] >= (uint32_t)-4095 || result[1] != PROT_READ) return 5;
    const char *mapping = (const char *)(uintptr_t)result[0];
    if (*mapping != 'V' || munmap((void *)mapping, 4096) || fclose(file)) return 6;
    puts("RAW_SYSCALL_386 calls=3 failures=0");
    return 0;
}
`
