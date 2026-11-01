//go:build darwin || linux

package plan9asm

import (
	"fmt"
	"runtime"
	"testing"
)

func TestX86PackedAverageE4PortableMemoryFaults(t *testing.T) {
	x86FixedBinaryE4PortableMemoryFaults(t, x86AverageValueRuntimeProgramWithResult, 90)
}

func TestX86PackedWordMultiplyE4PortableMemoryFaults(t *testing.T) {
	x86FixedBinaryE4PortableMemoryFaults(t, x86WordMultiplyValueRuntimeProgram, 180)
}

func TestX86PackedNarrowE4NFPortableMemoryFaults(t *testing.T) {
	x86FixedBinaryPortableMemoryFaults(t, x86NarrowValueRuntimeProgram, 270, true)
}

func x86FixedBinaryE4PortableMemoryFaults(t *testing.T, program func(string, bool) (string, string, string, string), observations int) {
	t.Helper()
	x86FixedBinaryPortableMemoryFaults(t, program, observations, false)
}

func x86FixedBinaryPortableMemoryFaults(t *testing.T, program func(string, bool) (string, string, string, string), observations int, fullTuple bool) {
	t.Helper()
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	full := 0
	if fullTuple {
		full = 1
	}
	for _, discard := range []bool{false, true} {
		source, declarations, prototypes, rows := program("amd64", discard)
		driver := "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n#include <errno.h>\n" +
			"#include <unistd.h>\n#include <signal.h>\n#include <sys/mman.h>\n#include <sys/wait.h>\n#include <sys/resource.h>\n" +
			numericalRuntimeFaultObservationC + prototypes + "\nstatic const int full_tuple=" + fmt.Sprint(full) + ";\n" + `
struct kernel {void (*fn)(uint8_t*,uint8_t*,uint8_t*,uint64_t);unsigned width,bits,mode,legacy,operation;};
static const struct kernel kernels[]={
` + rows + `};
static uint8_t *protected_region;
static size_t protected_bytes;
static int observe(const struct kernel *kernel,uint8_t *p,uint64_t mask,int fault) {
    pid_t child=fork();
    if(child<0)return 1;
    if(!child) {
        struct rlimit observed;
        uint8_t b[67],out[67];
        memset(b,0xa7,sizeof(b));
        memset(out,0xc3,sizeof(out));
        if(getrlimit(RLIMIT_CORE,&observed)||observed.rlim_cur||observed.rlim_max)_exit(120);
        numerical_fault_begin(p ? protected_region : 0,protected_bytes);
        kernel->fn(p,b+1,out+1,mask);
        _exit(0);
    }
    int status;
    pid_t waited;
    do {waited=waitpid(child,&status,0);}while(waited<0&&errno==EINTR);
    if(waited!=child)return 1;
    if(fault ? numerical_fault_status(status) : WIFEXITED(status)&&WEXITSTATUS(status)==0)return 0;
    fprintf(stderr,"average width=%u bits=%u mode=%u mask=%llx expectedFault=%d status=%x\n",
        kernel->width,kernel->bits,kernel->mode,(unsigned long long)mask,fault,status);
    return 1;
}
int main(void) {
    struct rlimit no_core={0,0};
    if(setrlimit(RLIMIT_CORE,&no_core))return 1;
    long page=sysconf(_SC_PAGESIZE);
    if(page<128)return 1;
    uint8_t *storage=mmap(0,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    if(storage==MAP_FAILED||mprotect(storage+page,page,PROT_NONE))return 1;
    memset(storage,0xa7,page);
    protected_region=storage+page;
    protected_bytes=(size_t)page;
    unsigned observations=0;
    for(unsigned row=0;row<sizeof(kernels)/sizeof(kernels[0]);row++) {
        const struct kernel *k=&kernels[row];
        if(k->legacy)continue; /* SSE's original aligned m128 opcode is a separate native axis. */
        unsigned tuple=k->width;
        if(full_tuple && (k->operation&2))tuple=k->bits/8;
        if(observe(k,0,0,full_tuple || k->mode==0)||observe(k,0,UINT64_MAX,1)||
            observe(k,storage+page-tuple,UINT64_MAX,0)||
            observe(k,storage+page-tuple+1,UINT64_MAX,1)||
            observe(k,storage+page-k->bits/8,1,full_tuple ? tuple>k->bits/8 : k->mode==0))return 1;
        observations+=5;
    }
    if(observations!=` + fmt.Sprint(observations) + `)return 1;
    return munmap(storage,2*page)!=0;
}
`
		triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(fmt.Sprintf("discard=%t/%s", discard, api), func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", triple, api)
				if err != nil {
					t.Fatal("complete typed packed source rejected", err)
				}
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []int{0, 2} {
						compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "average-e4-faults", triple, text, driver, nil, level)
					}
				}
			})
		}
	}
	t.Logf("all %d VEX/EVEX width/mask rows ×5 boundary controls ×live/dead results per backend, full-tuple=%t; portable LLVM, not native AVX512", observations/5, fullTuple)
}
