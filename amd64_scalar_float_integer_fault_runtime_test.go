//go:build unix

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86ScalarFloatIntegerDeadFaults(t *testing.T) {
	x86ScalarFloatIntegerDeadFaults(t, false, false)
}

func x86ScalarFloatIntegerDeadFaults(t *testing.T, vector, nativeTraps bool) {
	axis := x86FloatCompareSSE
	if vector {
		axis = x86FloatCompareEVEX
	}
	execution := x86FloatCompareRuntimeTools(t, axis)
	if nativeTraps && (runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || len(execution.prefix) != 0) {
		t.Fatal("unmasked MXCSR traps require the actual native Linux AMD64 counterpart")
	}
	var source, decl, native, prototypes, pairs strings.Builder
	count := 0
	for _, op := range x86ScalarFloatIntegerOracleNames() {
		if strings.HasPrefix(op, "V") != vector {
			continue
		}
		fn, original := fmt.Sprintf("fault%d", count), fmt.Sprintf("original%d", count)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-16\nMOVQ p+0(FP),DI\nMOVQ csr+8(FP),SI\nLDMXCSR (SI)\n%s (DI),AX\nXORL AX,AX\nRET\n", fn, op)
		fmt.Fprintf(&decl, "func %s(p *uint64,csr *uint32)\n", fn)
		code := x86PackedShiftActualGoBytes(t, "amd64", "TEXT f(SB),4,$0-0\nLDMXCSR (SI)\n"+op+" (DI),AX\nXORL AX,AX\nRET\n")
		var bytes []string
		for _, b := range code {
			bytes = append(bytes, fmt.Sprintf("0x%02x", b))
		}
		symbol := original
		if strings.Contains(execution.triple, "apple") {
			symbol = "_" + symbol
		}
		fmt.Fprintf(&native, "__asm__(%q);\n", ".text\n.globl "+symbol+"\n"+symbol+":\n.byte "+strings.Join(bytes, ",")+"\n")
		fmt.Fprintf(&prototypes, "extern void %s(uint64_t*,uint32_t*),%s(uint64_t*,uint32_t*);\n", fn, original)
		width := 4
		if strings.Contains(op, "SD") {
			width = 8
		}
		fmt.Fprintf(&pairs, "{%s,%s,%d},\n", original, fn, width)
		count++
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	trapChecks := 0
	if nativeTraps {
		trapChecks = 1
	}
	driver := fmt.Sprintf("#define NATIVE_TRAP_CHECKS %d\n", trapChecks) + `#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
` + native.String() + prototypes.String() + `
typedef void (*program)(uint64_t*,uint32_t*);
static const struct {program original,translated;int width;} pairs[]={
` + pairs.String() + `};
static int outcome(program fn,uint8_t *p,uint32_t csr) {
    pid_t child=fork();
    if(child<0) return -1;
    if(!child) {
        struct rlimit no_core={0,0};
        if(setrlimit(RLIMIT_CORE,&no_core)) _exit(120);
        fn((uint64_t*)p,&csr); _exit(0);
    }
    int status;
    if(waitpid(child,&status,0)!=child) return -1;
    if(WIFEXITED(status) && WEXITSTATUS(status)==0) return 0;
    if(WIFSIGNALED(status)) {
        int sig=WTERMSIG(status);
        if(sig==SIGSEGV || sig==SIGBUS) return 1;
        if(sig==SIGFPE) return 2;
    }
    return -1;
}
int main(void) {
    long page=sysconf(_SC_PAGESIZE);
    uint8_t *p=mmap(0,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    if(p==MAP_FAILED || mprotect(p+page,page,PROT_NONE)) return 2;
    memset(p,0,page);
    for(unsigned i=0;i<sizeof(pairs)/sizeof(*pairs);i++) {
        for(int available=0;available<=pairs[i].width+1;available++) {
            int want=available<pairs[i].width;
            int a=outcome(pairs[i].original,p+page-available,0x1f80);
            int b=outcome(pairs[i].translated,p+page-available,0x1f80);
            if(a!=want || b!=want) {
                fprintf(stderr,"dead scalar read=%u available=%d want=%d Go=%d LLVM=%d\n",i,available,want,a,b);
                return 3;
            }
        }
        for(int event=0;NATIVE_TRAP_CHECKS && event<2;event++) {
            uint64_t bits=pairs[i].width==8 ? (event?UINT64_C(0x3ff8000000000000):UINT64_C(0x7ff8123456789abc)) : (event?UINT64_C(0x3fc00000):UINT64_C(0x7fc12345));
            memcpy(p,&bits,8);
            uint32_t csr=event?0x0f80:0x1f00;
            int a=outcome(pairs[i].original,p,csr),b=outcome(pairs[i].translated,p,csr);
            if(a!=2 || b!=2) {
                fprintf(stderr,"dead scalar exception=%u event=%d Go=%d LLVM=%d\n",i,event,a,b);
                return 4;
            }
        }
    }
    if(munmap(p,2*page)) return 5;
    printf("original Go/LLVM dead scalar reads matched; native unmasked IE/PE checks=%d\n",NATIVE_TRAP_CHECKS);
    return 0;
}
`
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), decl.String(), "amd64", execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, pipeline := range []struct{ name, ir, level string }{
				{"backend_O0", ir, "-O0"}, {"IR_O2/backend_O2", x86MulDivRoundOptimize(t, ir), "-O2"},
			} {
				t.Run(pipeline.name, func(t *testing.T) {
					output := execution.compileAndRunLLVM(t, "scalar-dead-fault", pipeline.ir, driver, pipeline.level)
					if string(output) != fmt.Sprintf("original Go/LLVM dead scalar reads matched; native unmasked IE/PE checks=%d\n", trapChecks) {
						t.Fatal("missing complete dead-fault receipt", string(output))
					}
				})
			}
		})
	}
}
