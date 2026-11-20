//go:build unix

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// This root is required by the Linux cross-runtime matrix. Local Rosetta
// observations are diagnostic, not a replacement for native AMD64 execution.
func TestCrossLinuxRuntimeMatrixX86BitTestDeadMemoryFaults(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var source, declarations, native, prototypes, pairs strings.Builder
	count := 0
	for _, op := range x86BitTestOracleNames("amd64") {
		for _, index := range []string{"$0", "CX"} {
			name, original := fmt.Sprintf("dead%d", count), fmt.Sprintf("original%d", count)
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-16\nMOVQ p+0(FP),AX\nMOVQ index+8(FP),CX\n%s %s,(AX)\nRET\n", name, op, index)
			fmt.Fprintf(&declarations, "func %s(p *byte,index int64)\n", name)
			code := x86PackedShiftActualGoBytes(t, "amd64", "TEXT f(SB),4,$0-0\nMOVQ SI,CX\n"+op+" "+index+",(DI)\nRET\n")
			var bytes []string
			for _, b := range code {
				bytes = append(bytes, fmt.Sprintf("0x%02x", b))
			}
			symbol := original
			if strings.Contains(execution.triple, "apple") {
				symbol = "_" + symbol
			}
			fmt.Fprintf(&native, "__asm__(%q);\n", ".text\n.globl "+symbol+"\n"+symbol+":\n.byte "+strings.Join(bytes, ",")+"\n")
			fmt.Fprintf(&prototypes, "extern void %s(uint8_t*,int64_t),%s(uint8_t*,int64_t);\n", name, original)
			width := map[byte]int{'W': 2, 'L': 4, 'Q': 8}[op[len(op)-1]]
			indexed, writes := 0, 1
			if index == "CX" {
				indexed = 1
			}
			if len(op) == 3 {
				writes = 0
			}
			fmt.Fprintf(&pairs, "{%s,%s,%d,%d,%d},\n", original, name, width, indexed, writes)
			count++
		}
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	main := `
#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
` + prototypes.String() + native.String() + `
typedef void (*program)(uint8_t*,int64_t);
static const struct { program original,translated; int width,indexed,writes; } pairs[]={
` + pairs.String() + `};
static int outcome(program fn,uint8_t *p,int64_t index) {
    pid_t child=fork();
    if(child<0) return -1;
    if(!child) {
        struct rlimit no_core={0,0};
        if(setrlimit(RLIMIT_CORE,&no_core)) _exit(120);
        fn(p,index); _exit(0);
    }
    int status;
    if(waitpid(child,&status,0)!=child) return -1;
    if(WIFEXITED(status) && WEXITSTATUS(status)==0) return 0;
    if(WIFSIGNALED(status) && (WTERMSIG(status)==SIGSEGV || WTERMSIG(status)==SIGBUS)) return 1;
    return -1;
}
int main(void) {
    long page=sysconf(_SC_PAGESIZE);
    uint8_t *data=mmap(0,3*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    if(data==MAP_FAILED || mprotect(data+2*page,page,PROT_NONE)) return 2;
    memset(data,0xff,2*page);
    for(unsigned i=0;i<sizeof(pairs)/sizeof(*pairs);++i) {
        for(int shift=-1;shift<=1;++shift) {
            for(int available=0;available<=2*pairs[i].width;++available) {
                int displacement=pairs[i].indexed?shift*pairs[i].width:0;
                int expected=available-displacement<pairs[i].width;
                int64_t index=shift*8*pairs[i].width;
                int a=outcome(pairs[i].original,data+2*page-available,index);
                int b=outcome(pairs[i].translated,data+2*page-available,index);
                if(a!=expected || b!=expected) {
                    fprintf(stderr,"dead bit test=%u shift=%d available=%d want=%d Go=%d LLVM=%d\n",i,shift,available,expected,a,b);
                    return 1;
                }
            }
        }
    }
    for(int fill=0;fill<=255;fill+=255) {
        if(mprotect(data,page,PROT_READ|PROT_WRITE)) return 3;
        memset(data,fill,page);
        if(mprotect(data,page,PROT_READ)) return 3;
        for(unsigned i=0;i<sizeof(pairs)/sizeof(*pairs);++i) {
            int a=outcome(pairs[i].original,data+16,0);
            int b=outcome(pairs[i].translated,data+16,0);
            if(a!=pairs[i].writes || b!=pairs[i].writes) return 4;
        }
    }
    if(munmap(data,3*page)) return 5;
    puts("24 original Go/LLVM bit-string programs: dead full-width reads, signed offsets, read-only RMW");
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
					output := execution.compileAndRunLLVM(t, "bit-test-dead", pipeline.ir, main, pipeline.level)
					if string(output) != "24 original Go/LLVM bit-string programs: dead full-width reads, signed offsets, read-only RMW\n" {
						t.Fatalf("missing original/LLVM fault receipt: %s", output)
					}
				})
			}
		})
	}
}
