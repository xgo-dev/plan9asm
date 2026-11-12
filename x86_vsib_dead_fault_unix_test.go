//go:build darwin || linux

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86VSIBDeadGatherActiveLanesKeepMemoryFaults(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("portable VSIB fault execution requires its native 64-bit host counterpart")
	}
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var source, declarations, prototypes, rows strings.Builder
	for index, instruction := range []string{
		"VGATHERDPS X1,(AX)(X0*1),X2",
		"VGATHERDPD X1,(AX)(X0*1),X2",
		"VGATHERDPS (AX)(X16*1),K1,X18",
		"VGATHERDPD (AX)(X16*1),K1,X18",
	} {
		name := fmt.Sprint("DeadGather", index)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-16\nMOVQ p+0(FP),AX\nMOVQ mask+8(FP),CX\n", name)
		if index < 2 {
			source.WriteString("VPXOR Y0,Y0,Y0\nVPXOR Y2,Y2,Y2\nVMOVQ CX,X1\nVPSHUFD $0,X1,X1\n")
		} else {
			source.WriteString("VPXORD Z16,Z16,Z16\nVPXORD Z18,Z18,Z18\nKMOVQ CX,K1\n")
		}
		fmt.Fprintln(&source, instruction)
		source.WriteString("RET\n") // Both the gathered result and updated mask are dead.
		fmt.Fprintf(&declarations, "func %s(p *uint64,mask uint64)\n", name)
		fmt.Fprintf(&prototypes, "extern void %s(uint64_t *,uint64_t);\n", name)
		fmt.Fprintf(&rows, "%s,\n", name)
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	driver := "#include <stdint.h>\n#include <stdio.h>\n#include <signal.h>\n#include <sys/resource.h>\n#include <sys/wait.h>\n#include <unistd.h>\n" + prototypes.String() + `
int main(void) {
    void (*functions[])(uint64_t *,uint64_t) = {` + rows.String() + `};
    unsigned observations = 0;
    for (unsigned row = 0; row < sizeof(functions)/sizeof(functions[0]); ++row) {
        for (int active = 0; active < 2; ++active) {
            for (int valid = 0; valid < 2; ++valid) {
                pid_t child = fork();
                if (child < 0) return 1;
                if (!child) {
                    struct rlimit limit = {0,0};
                    if (setrlimit(RLIMIT_CORE,&limit)) _exit(120);
                    uint64_t value = UINT64_C(0x0123456789abcdef);
                    functions[row](valid ? &value : (uint64_t *)0,active ? UINT64_MAX : 0);
                    _exit(0);
                }
                int status = 0;
                if (waitpid(child,&status,0) != child) return 2;
                int fault = WIFSIGNALED(status) && (WTERMSIG(status) == SIGSEGV || WTERMSIG(status) == SIGBUS);
                int normal = WIFEXITED(status) && WEXITSTATUS(status) == 0;
                if ((active && !valid) ? !fault : !normal) {
                    fprintf(stderr,"dead-gather row=%u active=%d valid=%d status=%x\n",row,active,valid,status);
                    return 3;
                }
                ++observations;
            }
        }
    }
    return observations == 16 ? 0 : 4;
}
`
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, api)
			if err != nil {
				t.Fatal("initialized dead-result VSIB source rejected", err)
			}
			x86ConflictFunnelPortableRuntime(t, llc, clang, "dead-gather", triple, ir, driver)
		})
	}
}
