//go:build unix

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86ScalarCompareDeadReadFaults(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var source, declarations, native, prototypes, pairs strings.Builder
	for index, op := range x86ScalarCompareNames("amd64") {
		name, original := fmt.Sprintf("dead%d", index), fmt.Sprintf("original%d", index)
		// TEST $0 still reads its entire original memory operand. Neither its
		// tautological flags nor a later independent result may suppress faults.
		instruction := x86ScalarCompareInstruction(op, "(AX)", "$0")
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-8\nMOVQ p+0(FP),AX\n%s\nRET\n", name, instruction)
		fmt.Fprintf(&declarations, "func %s(p *byte)\n", name)
		code := x86PackedShiftActualGoBytes(t, "amd64", "TEXT f(SB),4,$0-0\n"+x86ScalarCompareInstruction(op, "(DI)", "$0")+"\nRET\n")
		var bytes []string
		for _, b := range code {
			bytes = append(bytes, fmt.Sprintf("0x%02x", b))
		}
		symbol := original
		if strings.Contains(execution.triple, "apple") {
			symbol = "_" + symbol
		}
		fmt.Fprintf(&native, "__asm__(%q);\n", ".text\n.globl "+symbol+"\n"+symbol+":\n.byte "+strings.Join(bytes, ",")+"\n")
		fmt.Fprintf(&prototypes, "extern void %s(uint8_t*),%s(uint8_t*);\n", name, original)
		fmt.Fprintf(&pairs, "{%s,%s,%d},\n", original, name, []int{1, 2, 4, 8}[index%4])
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	main := `
#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
` + prototypes.String() + native.String() + `
typedef void (*program)(uint8_t*);
static const struct { program original,translated; int width; } pairs[]={
` + pairs.String() + `};
static int outcome(program fn,uint8_t *p) {
    pid_t child=fork();
    if(child<0) return -1;
    if(!child) {
        struct rlimit no_core={0,0};
        if(setrlimit(RLIMIT_CORE,&no_core)) _exit(120);
        fn(p); _exit(0);
    }
    int status;
    if(waitpid(child,&status,0)!=child) return -1;
    if(WIFEXITED(status) && WEXITSTATUS(status)==0) return 0;
    if(WIFSIGNALED(status) && (WTERMSIG(status)==SIGSEGV || WTERMSIG(status)==SIGBUS)) return 1;
    return -1;
}
int main(void) {
    long page=sysconf(_SC_PAGESIZE);
    uint8_t *data=mmap(0,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    if(data==MAP_FAILED || mprotect(data+page,page,PROT_NONE)) return 2;
    for(unsigned i=0;i<sizeof(pairs)/sizeof(*pairs);++i) {
        for(int available=0;available<=8;++available) {
            int expected=available<pairs[i].width;
            int a=outcome(pairs[i].original,data+page-available);
            int b=outcome(pairs[i].translated,data+page-available);
            if(a!=expected || b!=expected) {
                fprintf(stderr,"dead compare=%u available=%d want=%d Go=%d LLVM=%d\n",i,available,expected,a,b);
                return 1;
            }
        }
    }
    if(munmap(data,2*page)) return 3;
    puts("8 compare/test dead reads x 9 guard extents");
    return 0;
}
`
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, pipeline := range []struct{ name, level, ir string }{
				{"backend_O0", "-O0", ir},
				{"IR_O2/backend_O2", "-O2", x86MulDivRoundOptimize(t, ir)},
			} {
				t.Run(pipeline.name, func(t *testing.T) {
					output := execution.compileAndRunLLVM(t, "scalar-compare-dead", pipeline.ir, main, pipeline.level)
					if string(output) != "8 compare/test dead reads x 9 guard extents\n" {
						t.Fatalf("missing whole-width Go/LLVM fault receipt: %s", output)
					}
				})
			}
		})
	}
}
