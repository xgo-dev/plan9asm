//go:build (darwin || linux) && (amd64 || arm64)

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// A pure LLVM/byte companion, not original Go or native AVX/AVX2 execution.
// Both halves are immediate zero and the result is dead. The original m256
// operand must nevertheless read all 32 bytes, with no alignment requirement.
func TestX86Permute128ActualHostDeadZeroTupleFaults(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	var source, declarations strings.Builder
	for index, member := range x86Permute128Members {
		name := fmt.Sprint("DeadPermute", index)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-8\nMOVQ p+0(FP),AX\n%s $136,(AX),Y1,Y2\nRET\n", name, member.op)
		fmt.Fprintf(&declarations, "func %s(p *byte)\n", name)
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, api)
			if err != nil || ir == "" {
				t.Fatal("genuine incoming-pointer dead-zero permute128 rejected", err)
			}
			if strings.Contains(ir, " asm ") || strings.Contains(ir, "target-features") {
				t.Fatal("portable tuple-fault companion contains native execution or an ISA constraint")
			}
			x86ConflictFunnelPortableRuntime(t, llc, clang, "permute128_dead_zero_faults", triple, ir,
				x86Permute128FaultHeader+numericalRuntimeFaultObservationC+x86Permute128FaultDriver)
		})
	}
}

const x86Permute128FaultHeader = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
extern void DeadPermute0(const uint8_t *);
extern void DeadPermute1(const uint8_t *);
typedef void (*Kernel)(const uint8_t *);
`

const x86Permute128FaultDriver = `
static int observe(Kernel run,const uint8_t *p,int fault,
                   uint8_t *protectedPage,size_t protectedBytes) {
    pid_t child=fork(); if(child<0) return 1;
    if(child==0) {
        struct rlimit no_core={0,0};
        if(setrlimit(RLIMIT_CORE,&no_core)) _exit(120);
        numerical_fault_begin(protectedPage,protectedBytes);
        run(p);
        // Do not touch p after the kernel: a C-side read must never turn
        // an elided native access into a false-positive expected fault.
        _exit(0);
    }
    int status=0; pid_t waited;
    do {waited=waitpid(child,&status,0);} while(waited<0 && errno==EINTR);
    if(waited!=child) return 1;
    int rejected=fault ? !numerical_fault_status(status) : !(WIFEXITED(status)&&WEXITSTATUS(status)==0);
    if(rejected) fprintf(stderr,"permute128 tuple input=%p expected-fault=%d owned=%p+%zu status=%#x\n",
                         (const void *)p,fault,(void *)protectedPage,protectedBytes,status);
    return rejected;
}
int main(void) {
    long page=sysconf(_SC_PAGESIZE); if(page<64) return 1;
    uint8_t *region=mmap(0,(size_t)page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    uint8_t *readonly=mmap(0,(size_t)page,PROT_READ,MAP_PRIVATE|MAP_ANON,-1,0);
    if(region==MAP_FAILED||readonly==MAP_FAILED||mprotect(region+page,(size_t)page,PROT_NONE)) return 2;
    const Kernel rows[]={DeadPermute0,DeadPermute1};
    int failed=0;
    for(size_t i=0;i<sizeof(rows)/sizeof(rows[0]);i++) {
        // Legalization may read either half first. Own exactly the m256
        // NULL tuple, not a single byte, a whole page or a C-side read.
        failed|=observe(rows[i],0,1,0,32);
        failed|=observe(rows[i],region+1,0,region+page,(size_t)page);
        failed|=observe(rows[i],region+page-32,0,region+page,(size_t)page);
        failed|=observe(rows[i],region+page-31,1,region+page,(size_t)page);
        failed|=observe(rows[i],readonly,0,region+page,(size_t)page);
    }
    failed|=munmap(region,(size_t)page*2)!=0;
    failed|=munmap(readonly,(size_t)page)!=0;
    return failed?3:0;
}
`

func TestX86Permute128FaultObserverPolicy(t *testing.T) {
	for _, control := range []string{
		"original", "missing-observer", "unowned-signal", "unchecked-core",
		"missing-EINTR", "narrow-null-span", "oversized-null-span",
	} {
		t.Run(control, func(t *testing.T) {
			driver := x86Permute128FaultDriver
			switch control {
			case "missing-observer":
				driver = strings.Replace(driver, "numerical_fault_begin(protectedPage,protectedBytes);", "", 1)
			case "unowned-signal":
				driver = strings.Replace(driver, "!numerical_fault_status(status)", "WIFSIGNALED(status)", 1)
			case "unchecked-core":
				driver = strings.Replace(driver, "if(setrlimit(RLIMIT_CORE,&no_core)) _exit(120);", "setrlimit(RLIMIT_CORE,&no_core);", 1)
			case "missing-EINTR":
				driver = strings.Replace(driver, "while(waited<0 && errno==EINTR)", "while(0)", 1)
			case "narrow-null-span":
				driver = strings.Replace(driver, "observe(rows[i],0,1,0,32)", "observe(rows[i],0,1,0,1)", 1)
			case "oversized-null-span":
				driver = strings.Replace(driver, "observe(rows[i],0,1,0,32)", "observe(rows[i],0,1,0,33)", 1)
			}
			if control != "original" && driver == x86Permute128FaultDriver {
				t.Fatal("fault policy negative did not change its actual driver")
			}
			setup := strings.Index(driver, "numerical_fault_begin(protectedPage,protectedBytes);")
			valid := runtimeOracleFaultCorePolicy(driver) == nil && setup >= 0 &&
				setup < strings.Index(driver, "run(p);") &&
				strings.Contains(driver, "while(waited<0 && errno==EINTR)") &&
				strings.Contains(driver, "if(waited!=child) return 1;") &&
				strings.Count(driver, "observe(rows[i],0,1,0,32)") == 1 &&
				strings.Contains(driver, "numerical_fault_status(status)") && !strings.Contains(driver, "WIFSIGNALED")
			if valid != (control == "original") {
				t.Fatal("fault observer lost ownership, core-limit or wait contract", control)
			}
		})
	}
}
