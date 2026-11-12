package plan9asm

import (
	"os"
	"path/filepath"
	"testing"
)

func x86PackedReductionNativeTools(t *testing.T) x86FloatCompareExecution {
	t.Helper()
	x86PackedReductionRequireNativeHost(t)
	execution := x86FloatCompareRuntimeTools(t, x86FloatCompareVEX)
	if execution.triple != "x86_64-unknown-linux-gnu" || len(execution.prefix) != 0 || execution.preserveArgv0 {
		t.Fatal("required native reductions cannot borrow guest or foreign execution")
	}
	directory := t.TempDir()
	source, executable := filepath.Join(directory, "reduction-cpu.c"), filepath.Join(directory, "reduction-cpu")
	if err := os.WriteFile(source, []byte(x86PackedReductionNativePreflightC), 0600); err != nil {
		t.Fatal(err)
	}
	execution.compileC(t, source, executable)
	t.Logf("actual native reduction CPU and all12 original opcodes: %s", execution.run(t, executable))
	return execution
}

func x86PackedReductionNativePipelines(t *testing.T, execution x86FloatCompareExecution, ir, driver string, want []byte) {
	t.Helper()
	if len(want) == 0 {
		t.Fatal("native reduction pipelines require original executed receipts")
	}
	for _, pipeline := range []struct {
		name, backend string
		optimize      bool
	}{
		{"backend_O0", "-O0", false},
		{"backend_O2", "-O2", false},
		{"IR_O2_backend_O2", "-O2", true},
	} {
		t.Run(pipeline.name, func(t *testing.T) {
			input := ir
			if pipeline.optimize {
				input = x86DwordProductIROptimize(t, ir)
			}
			got := execution.compileAndRunLLVM(t, "packed-reduction", input, driver, pipeline.backend)
			if string(got) != string(want) {
				t.Fatalf("original Go/native LLVM reductions differ\noriginal:\n%sLLVM:\n%s", want, got)
			}
		})
	}
}

const x86PackedReductionNativePreflightC = `#include <stdint.h>
#include <stdio.h>
#include <cpuid.h>

__attribute__((target("sse3,sse4.1,avx")))
static unsigned original_members(void) {
    unsigned members=0;
    unsigned csr=0x1f80;
    __asm__ volatile("ldmxcsr %0" :: "m"(csr) : "memory");
#define CHECK(OP,DST,BIT) do { \
    uint64_t out[4]; \
    __asm__ volatile("vxorps %%ymm0,%%ymm0,%%ymm0; " \
                     "vxorps %%ymm1,%%ymm1,%%ymm1; " \
                     "vxorps %%ymm2,%%ymm2,%%ymm2; " \
                     OP "; vmovups %%" DST ",%0" \
                     : "=m"(out) :: "ymm0","ymm1","ymm2","memory"); \
    for (unsigned i=0;i<4;i++) if(out[i]) return 0; \
    members|=1u<<(BIT); \
} while(0)
    CHECK("dppd $255,%%xmm0,%%xmm1","ymm1",0);
    CHECK("dpps $255,%%xmm0,%%xmm1","ymm1",1);
    CHECK("vdppd $255,%%xmm0,%%xmm1,%%xmm2","ymm2",2);
    CHECK("vdpps $255,%%ymm0,%%ymm1,%%ymm2","ymm2",3);
    CHECK("haddps %%xmm0,%%xmm1","ymm1",4);
    CHECK("haddpd %%xmm0,%%xmm1","ymm1",5);
    CHECK("hsubps %%xmm0,%%xmm1","ymm1",6);
    CHECK("hsubpd %%xmm0,%%xmm1","ymm1",7);
    CHECK("vhaddps %%ymm0,%%ymm1,%%ymm2","ymm2",8);
    CHECK("vhaddpd %%ymm0,%%ymm1,%%ymm2","ymm2",9);
    CHECK("vhsubps %%ymm0,%%ymm1,%%ymm2","ymm2",10);
    CHECK("vhsubpd %%ymm0,%%ymm1,%%ymm2","ymm2",11);
#undef CHECK
    return members;
}

int main(void) {
    unsigned a,b,c,d,sse3=0,sse41=0,avx=0,osxsave=0;
    uint64_t xcr0=0;
    if (__get_cpuid(1,&a,&b,&c,&d)) {
        sse3=c&1; sse41=(c>>19)&1; avx=(c>>28)&1; osxsave=(c>>27)&1;
        if (osxsave) {
            unsigned low,high;
            __asm__ volatile("xgetbv" : "=a"(low),"=d"(high) : "c"(0));
            xcr0=((uint64_t)high<<32)|low;
        }
    }
    printf("SSE3=%u SSE41=%u AVX=%u OSXSAVE=%u XCR0=%llx\n",
           sse3,sse41,avx,osxsave,(unsigned long long)xcr0);
    fflush(stdout);
    if (!sse3 || !sse41 || !avx || !osxsave || (xcr0&6)!=6) return 1;
    if (original_members()!=0xfff) return 2;
    puts("PACKED_REDUCTION_NATIVE_SSE3_SSE41_AVX_OK members=fff");
    return 0;
}
`
