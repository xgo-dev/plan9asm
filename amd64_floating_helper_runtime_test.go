package plan9asm

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func x86FloatingHelperRuntimeTools(t *testing.T) x86FloatCompareExecution {
	t.Helper()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("required native Linux/amd64 floating-helper execution counterpart; objects remain tested on every target")
	}
	execution := x86FloatCompareRuntimeTools(t, x86FloatCompareEVEX)
	// The shared EVEX owner already checks actual F/VL, OSXSAVE, XCR0,
	// original opcodes and native argv transport. RANGE/REDUCE/FPCLASS also
	// require DQ; neither an old receipt nor the host model name supplies it.
	directory := t.TempDir()
	source, executable := filepath.Join(directory, "dq.c"), filepath.Join(directory, "dq")
	if err := os.WriteFile(source, []byte(x86FloatingHelperDQPreflightC), 0600); err != nil {
		t.Fatal(err)
	}
	execution.compileC(t, source, executable)
	t.Logf("actual native floating-helper DQ/original-opcode preflight: %s", execution.run(t, executable))
	return execution
}

const x86FloatingHelperDQPreflightC = `#include <stdint.h>
#include <stdio.h>
#include <cpuid.h>

__attribute__((target("avx512f,avx512dq,avx512vl")))
static int original_dq(void) {
    unsigned packed, narrow, scalar;
    __asm__ volatile("vpxord %%zmm0,%%zmm0,%%zmm0; "
                     "vfpclassps $2,%%zmm0,%%k1; kmovw %%k1,%0; "
                     "vfpclassps $2,%%xmm0,%%k1; kmovw %%k1,%1; "
                     "vfpclasssd $2,%%xmm0,%%k1; kmovw %%k1,%2"
                     : "=r"(packed),"=r"(narrow),"=r"(scalar)
                     :: "zmm0","k1","memory");
    return packed==0xffff && narrow==0xf && scalar==1;
}

int main(void) {
    unsigned a,b,c,d,f=0,dq=0,vl=0,osxsave=0;
    uint64_t xcr0=0;
    if (__get_cpuid(1,&a,&b,&c,&d)) {
        osxsave=(c>>27)&1;
        if (osxsave) {
            unsigned low,high;
            __asm__ volatile("xgetbv" : "=a"(low),"=d"(high) : "c"(0));
            xcr0=((uint64_t)high<<32)|low;
        }
    }
    if (__get_cpuid_count(7,0,&a,&b,&c,&d)) {
        f=(b>>16)&1; dq=(b>>17)&1; vl=(b>>31)&1;
    }
    printf("AVX512F=%u AVX512DQ=%u AVX512VL=%u OSXSAVE=%u XCR0=%llx\n",
           f,dq,vl,osxsave,(unsigned long long)xcr0);
    fflush(stdout);
    if (!f || !dq || !vl || !osxsave || (xcr0&0xe6)!=0xe6) return 1;
    if (!original_dq()) return 2;
    puts("FLOATING_HELPER_NATIVE_DQ_OK");
    return 0;
}
`

func x86FloatingHelperRunNativePipelines(t *testing.T, execution x86FloatCompareExecution, name, ir, mainC string) {
	t.Helper()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || execution.triple != "x86_64-unknown-linux-gnu" ||
		len(execution.prefix) != 0 || execution.preserveArgv0 {
		t.Fatal("floating-helper native execution cannot borrow a guest or foreign target")
	}
	for _, pipeline := range []struct {
		name, backend string
		optimizeIR    bool
	}{
		{name: "backend_O0", backend: "-O0"},
		{name: "backend_O2", backend: "-O2"},
		{name: "IR_O2/backend_O2", backend: "-O2", optimizeIR: true},
	} {
		t.Run(pipeline.name, func(t *testing.T) {
			input := ir
			if pipeline.optimizeIR {
				input = x86DwordProductIROptimize(t, ir)
			}
			execution.compileAndRunLLVM(t, name, input, mainC, pipeline.backend)
		})
	}
}
