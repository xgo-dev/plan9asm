//go:build (darwin || linux) && (amd64 || arm64)

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Actual-host LLVM/C execution, not the original six-kernel Go/native owner.
// The source has only logical integer transport and scalar bit stores: no
// native SIMD opcode, MXCSR, CPU feature gate or emulator is needed here.
func TestX86LegacyScalarNativeStoreActualHostValuesAndDeadFaults(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	var source, declarations strings.Builder
	for _, row := range x86LegacyScalarNativeStoreRows {
		name := "Dead" + row.op
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-16\nMOVQ out+0(FP),BX\nMOVQ value+8(FP),X0\n%s X0,(BX)\n%s X0,(BX)\nRET\n",
			name, row.op, row.op)
		fmt.Fprintf(&declarations, "func %s(out *byte,value uint64)\n", name)
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	driver := x86LegacyScalarNativeStoreFaultHeader + numericalRuntimeFaultObservationC + x86LegacyScalarNativeStoreFaultDriver
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, api)
			if err != nil || ir == "" {
				t.Fatal("complete initialized scalar dead-store program rejected", err)
			}
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				x86LegacyScalarNativeStoreExactIR(t, text, 2)
			}
			x86ConflictFunnelPortableRuntime(t, llc, clang, "legacy_scalar_native_store_faults", triple, ir, driver)
		})
	}
}

const x86LegacyScalarNativeStoreFaultHeader = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
extern void DeadMOVSS(uint8_t *,uint64_t);
extern void DeadMOVSD(uint8_t *,uint64_t);
struct row {void (*run)(uint8_t *,uint64_t); size_t width; const char *name;};
static const struct row rows[]={{DeadMOVSS,4,"MOVSS"},{DeadMOVSD,8,"MOVSD"}};
`

const x86LegacyScalarNativeStoreFaultDriver = `
static int observe(const struct row *test,uint8_t *p,uint64_t value,int fault,
                   uint8_t *protectedPage,size_t protectedBytes) {
    pid_t child=fork(); if(child<0) return 1;
    if(child==0) {
        struct rlimit no_core={0,0};
        if(setrlimit(RLIMIT_CORE,&no_core)) _exit(120);
        numerical_fault_begin(protectedPage,protectedBytes);
        uint8_t before=fault ? 0 : p[-1];
        test->run(p,value);
        // Never touch an expected-fault address after the oracle: that
        // could turn an elided store into a false-positive C-side fault.
        if(!fault) {
            for(size_t b=0;b<test->width;b++) {
                if(p[b]!=(uint8_t)(value>>(8*b))) _exit(124);
            }
            if(p[-1]!=before) _exit(125);
            if((uintptr_t)(p+test->width)<(uintptr_t)protectedPage &&
               p[test->width]!=0xa5) _exit(126);
        }
        _exit(0);
    }
    int status=0; pid_t waited;
    do {waited=waitpid(child,&status,0);} while(waited<0 && errno==EINTR);
    if(waited!=child) return 1;
    if(fault ? numerical_fault_status(status) : (WIFEXITED(status)&&WEXITSTATUS(status)==0)) return 0;
    fprintf(stderr,"%s width=%zu fault=%d value=%llx status=%x\n",
            test->name,test->width,fault,(unsigned long long)value,status);
    return 1;
}
int main(void) {
    long page=sysconf(_SC_PAGESIZE); if(page<64) return 1;
    uint8_t *region=mmap(0,(size_t)page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    uint8_t *readonly=mmap(0,(size_t)page,PROT_READ,MAP_PRIVATE|MAP_ANON,-1,0);
    if(region==MAP_FAILED||readonly==MAP_FAILED||mprotect(region+page,(size_t)page,PROT_NONE)) return 1;
    memset(region,0xa5,(size_t)page);
    const uint64_t values[]={0,UINT64_MAX,UINT64_C(0x7ff0000000000001),UINT64_C(0x1234567880000001)};
    for(size_t r=0;r<sizeof(rows)/sizeof(rows[0]);r++) {
        const struct row *test=&rows[r];
        for(size_t v=0;v<sizeof(values)/sizeof(values[0]);v++) {
            if(observe(test,0,values[v],1,0,1)||
               observe(test,region+page-test->width,values[v],0,region+page,(size_t)page)||
               observe(test,region+page-test->width+1,values[v],1,region+page,(size_t)page)||
               observe(test,region+1,values[v],0,region+page,(size_t)page)||
               observe(test,readonly,values[v],1,readonly,(size_t)page)) return 2;
        }
    }
    int failed=munmap(region,(size_t)page*2)!=0;
    failed|=munmap(readonly,(size_t)page)!=0;
    return failed?3:0;
}
`

func TestX86LegacyScalarNativeStoreFaultObserverPolicy(t *testing.T) {
	if err := runtimeOracleFaultCorePolicy(x86LegacyScalarNativeStoreFaultDriver); err != nil {
		t.Fatal(err)
	}
	for _, control := range []string{"original", "missing-observer", "unchecked-core-limit", "missing-EINTR", "unowned-signal"} {
		t.Run(control, func(t *testing.T) {
			driver := x86LegacyScalarNativeStoreFaultDriver
			switch control {
			case "missing-observer":
				driver = strings.Replace(driver, "numerical_fault_begin(protectedPage,protectedBytes);", "", 1)
			case "unchecked-core-limit":
				driver = strings.Replace(driver, "if(setrlimit(RLIMIT_CORE,&no_core)) _exit(120);", "setrlimit(RLIMIT_CORE,&no_core);", 1)
			case "missing-EINTR":
				driver = strings.Replace(driver, "waited<0 && errno==EINTR", "0", 1)
			case "unowned-signal":
				driver = strings.Replace(driver, "numerical_fault_status(status)", "WIFSIGNALED(status)", 1)
			}
			setup := strings.Index(driver, "numerical_fault_begin(protectedPage,protectedBytes);")
			valid := runtimeOracleFaultCorePolicy(driver) == nil && setup >= 0 &&
				setup < strings.Index(driver, "test->run(p,value);") &&
				strings.Contains(driver, "while(waited<0 && errno==EINTR)") &&
				strings.Contains(driver, "if(waited!=child) return 1;") &&
				strings.Contains(driver, "numerical_fault_status(status)") && !strings.Contains(driver, "WIFSIGNALED")
			if valid != (control == "original") || control != "original" && driver == x86LegacyScalarNativeStoreFaultDriver {
				t.Fatal("guard-page child lost synchronous owned-address or resource policy", control)
			}
		})
	}
}
