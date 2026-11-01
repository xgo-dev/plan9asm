//go:build unix

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// This oracle's original C uses only integers and POSIX page protection. It
// executes the portable lowering on the actual host, not an AVX512 instruction
// or MXCSR substitute. The separate MXCSR value owner keeps its x86 tools.
func x86TernaryGuardPageRuntimeTools(t *testing.T) (llc, clang, triple string, prefix []string) {
	t.Helper()
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	return llc, clang, testTargetTriple(runtime.GOOS, runtime.GOARCH), nil
}

// E4 permits suppression by inactive mask lanes, not by a constant truth table
// or a dead destination. This portable guard-page oracle does not execute
// original AVX512 instructions; actual Go objects establish source acceptance.
func TestCrossLinuxRuntimeMatrixX86TernaryDeadReadsAndMaskedFaults(t *testing.T) {
	llc, clang, triple, prefix := x86TernaryGuardPageRuntimeTools(t)
	var source, declarations, cases strings.Builder
	sigs := map[string]FuncSig{}
	count := 0
	for _, bits := range []int{32, 64} {
		for width, bank := range map[int]string{16: "X", 32: "Y", 64: "Z"} {
			for broadcast := 0; broadcast < 2; broadcast++ {
				for masking := 0; masking < 3; masking++ {
					name := fmt.Sprint("ternaryFault", count)
					count++
					op := "VPTERNLOGD"
					if bits == 64 {
						op = "VPTERNLOGQ"
					}
					if broadcast != 0 {
						op += ".BCST"
					}
					if masking == 2 {
						op += ".Z"
					}
					mask := ""
					if masking != 0 {
						mask = ",K1"
					}
					fmt.Fprintf(&source, "TEXT %s(SB),4,$0-16\nMOVQ p+0(FP),AX\nMOVQ k+8(FP),CX\nKMOVQ CX,K1\n%s $0,(AX),%s1%s,%s2\nRET\n", name, op, bank, mask, bank)
					sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, I64}, Ret: Void,
						Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: I64, Index: 1, Field: -1}}}}
					fmt.Fprintf(&declarations, "extern void %s(const uint8_t*,uint64_t);\n", name)
					fmt.Fprintf(&cases, "{%s,%d,%d,%d,%d},\n", name, width, bits/8, broadcast, masking)
				}
			}
		}
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	driver := `#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
struct test {void (*run)(const uint8_t*,uint64_t);unsigned width,lane,broadcast,mask;};
` + declarations.String() + "static const struct test cases[]={\n" + cases.String() + `};
static int observe(const struct test *test,const uint8_t *p,uint64_t mask) {
    pid_t child=fork();
    if(child<0) return -1;
    if(child==0) {
        struct rlimit no_core={0,0};
        if(setrlimit(RLIMIT_CORE,&no_core)) _exit(120);
        test->run(p,mask);
        _exit(0);
    }
    int status=0;
    if(waitpid(child,&status,0)!=child) return -2;
    if(WIFEXITED(status) && WEXITSTATUS(status)==0) return 0;
    if(WIFSIGNALED(status) && (WTERMSIG(status)==SIGSEGV || WTERMSIG(status)==SIGBUS)) return 1;
    return -3;
}
int main(void) {
    long page=sysconf(_SC_PAGESIZE);
    if(page<128) return 1;
    uint8_t *region=mmap(0,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    if(region==MAP_FAILED || mprotect(region+page,page,PROT_NONE)) return 2;
    for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);i++) {
        const struct test *test=cases+i;
        unsigned lanes=test->width/test->lane;
        uint64_t masks[]={0,1,UINT64_C(1)<<(lanes-1),UINT64_C(1)<<63,UINT64_MAX};
        unsigned extents[]={0,test->lane-1,test->lane,test->width-1,test->width};
        for(unsigned m=0;m<5;m++) for(unsigned e=0;e<5;e++) {
            unsigned required=0;
            for(unsigned lane=0;lane<lanes;lane++) {
                if(!test->mask || (masks[m]>>lane&1))
                    required=test->broadcast?test->lane:(lane+1)*test->lane;
            }
            int expected=required>extents[e];
            int got=observe(test,region+page-extents[e],masks[m]);
            if(got!=expected) {
                fprintf(stderr,"case=%u mask=%llx extent=%u got=%d want=%d\n",i,(unsigned long long)masks[m],extents[e],got,expected);
                return 3;
            }
        }
    }
    return munmap(region,2*page)!=0;
}
`
	for _, optimize := range []bool{false, true} {
		text := ir
		if optimize {
			text = x86MulDivRoundOptimize(t, text)
		}
		t.Run(fmt.Sprint("IR_O2=", optimize), func(t *testing.T) {
			compileAndRunRuntimeTestForTarget(t, llc, clang, "ternary-faults", triple, text, driver, prefix)
		})
	}
	t.Logf("%d E4 forms x5 masks x5 guard extents x2 IR pipelines; constant truth/dead output remains observable", count)
}
