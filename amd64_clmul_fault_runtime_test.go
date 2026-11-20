//go:build unix

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86CLMULOriginalDeadReadFaults(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var source, references, pairs strings.Builder
	sigs := map[string]FuncSig{}
	for index, immediate := range []int{0, 1, 16, 17} {
		name := fmt.Sprint("clmulfault", index)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-8\nMOVQ p+0(FP),AX\nPXOR X1,X1\nPCLMULQDQ $%d,(AX),X1\nRET\n", name, immediate)
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}}}
		code := x86OrderingHintGoBytes(t, "amd64", fmt.Sprintf("TEXT f(SB),4,$0-0\nPCLMULQDQ $%d,(DI),X1\nRET\n", immediate))
		if len(code) != 7 || code[len(code)-1] != 0xc3 {
			t.Fatal("original memory opcode or its RET changed", code)
		}
		var bytes []string
		for _, value := range code[:len(code)-1] {
			bytes = append(bytes, fmt.Sprintf("0x%02x", value))
		}
		fmt.Fprintf(&references, "extern void %s(const void*);\nstatic void original%d(const void *p) {\n", name, index)
		fmt.Fprintf(&references, "    __asm__ volatile(\"pxor %%%%xmm1, %%%%xmm1; .byte %s\"::\"D\"(p):\"xmm1\",\"memory\");\n}\n", strings.Join(bytes, ","))
		if index > 0 {
			pairs.WriteString(",")
		}
		fmt.Fprintf(&pairs, "{original%d,%s}", index, name)
	}
	oracle := `#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
` + references.String() + `
typedef void (*operation)(const void*);
struct pair {operation original,translated;};
static const struct pair pairs[]={ ` + pairs.String() + ` };
static int outcome(operation fn,const void *p) {
    pid_t pid=fork(); if(pid<0) return -1;
    if(!pid) {
        struct rlimit limit={0,0}; if(setrlimit(RLIMIT_CORE,&limit)) _exit(120);
        fn(p); _exit(0);
    }
    int status; if(waitpid(pid,&status,0)!=pid) return -1;
    if(WIFEXITED(status) && WEXITSTATUS(status)==0) return 0;
    if(WIFSIGNALED(status)) return WTERMSIG(status);
    return -1;
}
int main(void) {
    long page=sysconf(_SC_PAGESIZE); if(page<128) return 1;
    uint8_t *region=mmap(0,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(region==MAP_FAILED || mprotect(region+page,page,PROT_NONE)) return 2;
    for(unsigned op=0;op<4;op++) for(unsigned extent=0;extent<=32;extent++) {
        const void *p=region+page-extent;
        int original=outcome(pairs[op].original,p),translated=outcome(pairs[op].translated,p);
        if(original<0 || original!=translated || (extent==32 && original!=0) ||
           (extent==0 && original!=SIGSEGV && original!=SIGBUS)) {
            fprintf(stderr,"CLMUL selector=%u extent=%u original=%d translated=%d\n",op,extent,original,translated);
            return 3;
        }
    }
    for(unsigned op=0;op<4;op++) {
        int original=outcome(pairs[op].original,0),translated=outcome(pairs[op].translated,0);
        if(original!=translated || (original!=SIGSEGV && original!=SIGBUS)) return 4;
    }
    return munmap(region,2*page)!=0;
}
`
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprintf("IR_O2=%t", optimized), func(t *testing.T) {
			text := ir
			if optimized {
				text = x86MulDivRoundOptimize(t, text)
			}
			compileAndRunRuntimeTestForTarget(t, llc, clang, "clmul-original-dead-faults", triple, text, oracle, prefix)
		})
	}
}
