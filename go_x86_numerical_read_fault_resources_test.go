//go:build go1.27 && unix

package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the complete generated carriers, not isolated resource-policy text.
// Every fault child must disable both core limits before mprotect or a call;
// an expected SIGSEGV is an oracle result, not permission to create core files.
func TestGoX86NumericalSBReadRuntimeFaultCorePolicy(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		cases := numericalExecutionCases(arch)
		carriers := []struct {
			name   string
			source string
		}{
			{"mutable", numericalRuntimeC(cases, arch)},
			{"width", numericalRuntimeWidthFaultC(cases, arch)},
		}
		if arch == "amd64" {
			carriers = append(carriers, struct {
				name   string
				source string
			}{"local", numericalLocalRuntimeC(0x8877665544332211)})
		}
		for _, carrier := range carriers {
			t.Run(arch+"/"+carrier.name, func(t *testing.T) {
				if !strings.Contains(carrier.source, "#include <sys/resource.h>") {
					t.Error("complete C carrier must include its actual resource declarations")
				}
				if err := runtimeOracleFaultCorePolicy(carrier.source); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// The same handler used by every carrier must observe a real synchronous fault
// in its protected range. Raised signals, another range, normal returns and
// malformed signal metadata are independently rejected by the compiled helper.
func TestGoX86NumericalSBReadRuntimeFaultObservation(t *testing.T) {
	_, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 clang required for the actual fault observation")
	}
	source := `#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
` + numericalRuntimeFaultObservationC + `
int main(void) {
    long page=sysconf(_SC_PAGESIZE);
    if(page<=0) return 10;
    unsigned char *region=mmap(0,page*2,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(region==MAP_FAILED) return 11;
    for(unsigned mode=0;mode<7;mode++) {
        pid_t child=fork();
        if(child<0) return 12;
        if(!child) {
            struct rlimit no_core={0,0};
            if(setrlimit(RLIMIT_CORE,&no_core)) _exit(120);
            numerical_fault_begin(mode==1 ? region+page : region,page);
            struct rlimit observed;
            if(getrlimit(RLIMIT_CORE,&observed) || observed.rlim_cur ||
                observed.rlim_max) _exit(124);
            if(mode==2) {
                raise(SIGSEGV);
                _exit(125);
            }
            if(mode==3) _exit(0);
            if(mode>=4) {
                siginfo_t info;
                memset(&info,0,sizeof(info));
                info.si_signo=mode==4 ? SIGBUS : SIGSEGV;
                info.si_code=mode==5 ? 0 : 1;
                info.si_addr=mode==6 ? region+page : region;
                numerical_fault_observe(SIGSEGV,&info,0);
                _exit(126);
            }
            if(mprotect(region,page,PROT_NONE)) _exit(127);
            volatile unsigned char value=*region;
            _exit(value);
        }
        int status=0;
        if(waitpid(child,&status,0)!=child) return 13;
        if(!WIFEXITED(status)) return 14;
        int expected=mode==0 ? 123 : mode==3 ? 0 : 121;
        if(WEXITSTATUS(status)!=expected) return 15;
        if(numerical_fault_status(status)!=(mode==0)) return 16;
    }
    return munmap(region,page*2)!=0;
}
`
	directory := t.TempDir()
	input, executable := filepath.Join(directory, "fault.c"), filepath.Join(directory, "fault")
	if err := os.WriteFile(input, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			x86FloatCompareCaptureCommand(t, runtimeOracleNativeCCommand(t, ctx, clang, level, input, "-o", executable))
			if output := x86FloatCompareCaptureCommand(t, exec.Command(executable)); len(output) != 0 {
				t.Fatal("unexpected numerical fault-observation output", string(output))
			}
		})
	}
}
