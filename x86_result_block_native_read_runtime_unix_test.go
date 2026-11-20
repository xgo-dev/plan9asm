//go:build unix

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// This portable test executes the complete result-analysis path. It checks
// continuation bytes and E6NF full-tuple faults, not native AVX512 execution.
func TestCrossLinuxRuntimeMatrixX86BlockInsertResultFullTupleFaults(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var source, declarations, prototypes, cases strings.Builder
	count := 0
	for _, chunk := range []int{16, 32} {
		for mode := 0; mode < 3; mode++ {
			for _, dead := range []bool{false, true} {
				op, mask := "VINSERTF32X4", ""
				if chunk == 32 {
					op = "VINSERTI64X4"
				}
				if mode != 0 {
					mask = "K1,"
				}
				if mode == 2 {
					op += ".Z"
				}
				tail, discarded := "", 0
				if dead {
					tail, discarded = "VPXORQ Z2,Z2,Z2\n", 1
				}
				name := fmt.Sprintf("insert_result%d", count)
				fmt.Fprintf(&declarations, "func %s(p *[32]byte, mask uint32) uint32\n", name)
				fmt.Fprintf(&source, `TEXT ·%s(SB),4,$0-20
MOVQ p+0(FP),AX
MOVL mask+8(FP),CX
KMOVW CX,K1
VPXORQ Z1,Z1,Z1
VPXORQ Z2,Z2,Z2
MOVL $0x12345678,DX
PINSRD $0,DX,X2
%s $0,(AX),Z1,%sZ2
%sPEXTRD $0,X2,AX
MOVL AX,ret+16(FP)
RET
`, name, op, mask, tail)
				fmt.Fprintf(&prototypes, "extern uint32_t %s(const uint8_t*,uint32_t);\n", name)
				fmt.Fprintf(&cases, "{%s,%d,%d,%d},\n", name, chunk, mode, discarded)
				count++
			}
		}
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, "Go")
	if err != nil {
		t.Fatal(err)
	}
	driver := `#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
struct test {uint32_t (*run)(const uint8_t*,uint32_t); unsigned width,mode,dead;};
` + prototypes.String() + "static const struct test cases[]={\n" + cases.String() + `};
static int fault(const struct test *test,const uint8_t *p,uint32_t mask) {
    pid_t child=fork();
    if(child<0) return -1;
    if(child==0) {
        struct rlimit no_core={0,0};
        if(setrlimit(RLIMIT_CORE,&no_core)) _exit(120);
        volatile uint32_t value=test->run(p,mask);
        (void)value;
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
    memset(region,0x57,page);
    uint32_t masks[]={0,1,UINT32_C(0x80000000),UINT32_MAX};
    for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);i++) {
        const struct test *test=cases+i;
        unsigned extents[]={0,test->width/2,test->width-1,test->width};
        for(unsigned m=0;m<4;m++) {
            uint32_t want=UINT32_C(0x57575757);
            if(test->mode && !(masks[m]&1)) want=test->mode==1?UINT32_C(0x12345678):0;
            if(test->dead) want=0;
            if(test->run(region+1,masks[m])!=want) return 3;
            /* E6NF still accesses every source byte with a zero mask, an
               ignored high mask bit or an independently replaced result. */
            if(fault(test,0,masks[m])!=1) return 4;
            for(unsigned e=0;e<4;e++) {
                int got=fault(test,region+page-extents[e],masks[m]);
                if(got!=(extents[e]<test->width)) {
                    fprintf(stderr,"case=%u mask=%x extent=%u result=%d\n",i,masks[m],extents[e],got);
                    return 5;
                }
            }
        }
    }
    return munmap(region,2*page)!=0;
}
`
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprintf("IR_O2=%t", optimized), func(t *testing.T) {
			text := ir
			if optimized {
				text = x86MulDivRoundOptimize(t, text)
			}
			compileAndRunRuntimeTestForTarget(t, llc, clang, "insert-result-faults", triple, text, driver, prefix)
		})
	}
}
