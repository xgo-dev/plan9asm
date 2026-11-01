//go:build unix

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86COMIDeadMemoryExtent(t *testing.T) {
	x86COMIDeadFaults(t, false)
}

func x86COMIDeadFaults(t *testing.T, native bool) {
	t.Helper()
	axis := x86FloatCompareSSE
	if native {
		axis = x86FloatCompareEVEX
	}
	execution := x86FloatCompareRuntimeTools(t, axis)
	if native && (runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || len(execution.prefix) != 0) {
		t.Fatal("COMI exception delivery requires actual native Linux AMD64")
	}
	assembly, declarations, driver, _, trapChecks := x86COMIDeadFaultFixture(t, native, execution.triple)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, assembly, declarations, "amd64", execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, pipeline := range []struct{ name, ir, level string }{
				{"backend_O0", ir, "-O0"}, {"IR_O2/backend_O2", x86MulDivRoundOptimize(t, ir), "-O2"},
			} {
				t.Run(pipeline.name, func(t *testing.T) {
					output := execution.compileAndRunLLVM(t, "comi-fault", pipeline.ir, driver, pipeline.level)
					want := fmt.Sprintf("COMI original Go/LLVM dead reads matched; native IE/DE/SAE checks=%d\n", trapChecks)
					if string(output) != want {
						t.Fatal("missing complete fault receipt", string(output))
					}
				})
			}
		})
	}
}

func x86COMIDeadFaultFixture(t *testing.T, native bool, triple string) (string, string, string, int, int) {
	t.Helper()
	var assembly, declarations, original, prototypes, pairs strings.Builder
	count := 0
	for _, name := range x86COMIOracleNames() {
		if strings.HasPrefix(name, "V") && !native {
			continue
		}
		suffixes := []string{""}
		if strings.HasPrefix(name, "V") {
			suffixes = append(suffixes, ".SAE")
		}
		for _, suffix := range suffixes {
			width, load := 4, "MOVSS"
			if strings.HasSuffix(name, "D") {
				width, load = 8, "MOVSD"
			}
			body := "XORPS X1,X1\nLDMXCSR (SI)\n" + name + " (DI),X1\n"
			if suffix != "" {
				body = "XORPS X1,X1\n" + load + " (DI),X0\nLDMXCSR (SI)\n" + name + suffix + " X0,X1\n"
			}
			body += "XORL AX,AX\nRET\n" // The comparison FLAGS are deliberately dead.
			function, nativeFunction := fmt.Sprintf("fault%d", count), fmt.Sprintf("original%d", count)
			fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-16\nMOVQ p+0(FP),DI\nMOVQ csr+8(FP),SI\n%s", function, body)
			fmt.Fprintf(&declarations, "func %s(p *uint64,csr *uint32)\n", function)
			code := x86PackedShiftActualGoBytes(t, "amd64", "TEXT f(SB),4,$0-0\n"+body)
			bytes := make([]string, len(code))
			for index, value := range code {
				bytes[index] = fmt.Sprintf("0x%02x", value)
			}
			symbol := nativeFunction
			if strings.Contains(triple, "apple") {
				symbol = "_" + symbol
			}
			fmt.Fprintf(&original, "__asm__(%q);\n", ".text\n.globl "+symbol+"\n"+symbol+":\n.byte "+strings.Join(bytes, ",")+"\n")
			fmt.Fprintf(&prototypes, "extern void %s(uint64_t*,uint32_t*),%s(uint64_t*,uint32_t*);\n", function, nativeFunction)
			quiet, sae := 0, 0
			if strings.Contains(name, "UCOMI") {
				quiet = 1
			}
			if suffix != "" {
				sae = 1
			}
			fmt.Fprintf(&pairs, "{%s,%s,%d,%d,%d},\n", nativeFunction, function, width, quiet, sae)
			count++
		}
	}
	goAssemblerOracleOutput(t, "amd64", assembly.String(), "", true)
	trapChecks := 0
	if native {
		trapChecks = 1
	}
	driver := fmt.Sprintf("#define NATIVE_TRAPS %d\n", trapChecks) + `
#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
` + original.String() + prototypes.String() + `
typedef void (*kernel)(uint64_t*,uint32_t*);
static const struct {kernel original,translated;int width,quiet,sae;} pairs[]={
` + pairs.String() + `};
static int outcome(kernel fn,uint8_t *p,uint32_t csr) {
    pid_t child=fork();
    if(child<0) return -1;
    if(!child) {
        struct rlimit no_core={0,0};
        if(setrlimit(RLIMIT_CORE,&no_core)) _exit(120);
        fn((uint64_t*)p,&csr);
        _exit(0);
    }
    int status;
    if(waitpid(child,&status,0)!=child) return -1;
    if(WIFEXITED(status) && WEXITSTATUS(status)==0) return 0;
    if(WIFSIGNALED(status)) {
        int signal=WTERMSIG(status);
        if(signal==SIGSEGV || signal==SIGBUS) return 1;
        if(signal==SIGFPE) return 2;
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
                fprintf(stderr,"COMI dead read %u available=%d want=%d Go=%d LLVM=%d\n",i,available,want,a,b);
                return 3;
            }
        }
        for(int event=0;NATIVE_TRAPS && event<3;event++) {
            uint64_t bits;
            if(pairs[i].width==8)
                bits=event==0?UINT64_C(0x7ff8123456789abc):event==1?UINT64_C(0x7ff0123456789abc):1;
            else
                bits=event==0?UINT64_C(0x7fc12345):event==1?UINT64_C(0x7f812345):1;
            memcpy(p,&bits,8);
            uint32_t csr=event==2?0x1e80:0x1f00;
            int want=pairs[i].sae || (event==0 && pairs[i].quiet)?0:2;
            int a=outcome(pairs[i].original,p,csr),b=outcome(pairs[i].translated,p,csr);
            if(a!=want || b!=want) {
                fprintf(stderr,"COMI exception %u event=%d want=%d Go=%d LLVM=%d\n",i,event,want,a,b);
                return 4;
            }
        }
    }
    if(munmap(p,2*page)) return 5;
    printf("COMI original Go/LLVM dead reads matched; native IE/DE/SAE checks=%d\n",NATIVE_TRAPS);
    return 0;
}
`
	return assembly.String(), declarations.String(), driver, count, trapChecks
}
