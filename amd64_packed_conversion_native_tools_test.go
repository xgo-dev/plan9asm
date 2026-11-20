package plan9asm

import (
	"os"
	"path/filepath"
	"testing"
)

func x86PackedConversionNativeTools(t *testing.T) x86FloatCompareExecution {
	t.Helper()
	x86PackedConversionRequireNativeHost(t)
	execution := x86FloatCompareRuntimeTools(t, x86FloatCompareEVEX)
	directory := t.TempDir()
	source := filepath.Join(directory, "packed-conversion-cpu.c")
	executable := filepath.Join(directory, "packed-conversion-cpu")
	if err := os.WriteFile(source, []byte(x86PackedConversionNativePreflightC), 0600); err != nil {
		t.Fatal(err)
	}
	execution.compileC(t, source, executable)
	t.Logf("actual native packed conversion CPU/opcode preflight: %s", execution.run(t, executable))
	return execution
}

func x86PackedConversionNativePipelines(t *testing.T, execution x86FloatCompareExecution, ir, driver string, want []byte) {
	t.Helper()
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
			got := execution.compileAndRunLLVM(t, "packed-conversion", input, driver, pipeline.backend)
			if string(got) != string(want) {
				t.Fatalf("original native/LLVM receipt differs\noriginal:\n%sLLVM:\n%s", want, got)
			}
		})
	}
}

// This preflight executes original whole opcodes only after both CPUID and
// actual OS register state pass. A missing feature or a failed opcode is an
// infrastructure failure, never a skipped or portable runtime certificate.
const x86PackedConversionNativePreflightC = `#include <stdint.h>
#include <stdio.h>
#include <cpuid.h>

__attribute__((target("avx512f,avx512dq,avx512bw,avx512vl")))
static int original_conversion_opcodes(void) {
    _Alignas(64) uint64_t qwords[8]={0};
    _Alignas(16) uint32_t dwords[4]={0};
    uint64_t mask;
    __asm__ volatile("vpxord %%zmm0,%%zmm0,%%zmm0; "
                     "vcvtqq2pd %%zmm0,%%zmm1; vmovdqu64 %%zmm1,%0; "
                     "kxnorq %%k1,%%k1,%%k1; kmovq %%k1,%2; "
                     "vcvtdq2ps %%xmm0,%%xmm1%{%%k1%}%{z%}; vmovdqu32 %%xmm1,%1"
                     : "=m"(qwords),"=m"(dwords),"=&r"(mask)
                     :: "zmm0","zmm1","k1","memory");
    for (unsigned i=0;i<8;i++) if (qwords[i]) return 0;
    for (unsigned i=0;i<4;i++) if (dwords[i]) return 0;
    return mask==UINT64_MAX;
}

int main(void) {
    unsigned a,b,c,d,f=0,dq=0,bw=0,vl=0,osxsave=0;
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
        f=(b>>16)&1; dq=(b>>17)&1; bw=(b>>30)&1; vl=(b>>31)&1;
    }
    printf("AVX512F=%u AVX512DQ=%u AVX512BW=%u AVX512VL=%u OSXSAVE=%u XCR0=%llx\n",
           f,dq,bw,vl,osxsave,(unsigned long long)xcr0);
    fflush(stdout);
    if (!f || !dq || !bw || !vl || !osxsave || (xcr0&0xe6)!=0xe6) return 1;
    if (!original_conversion_opcodes()) return 2;
    puts("PACKED_CONVERSION_NATIVE_F_DQ_BW_VL_OK");
    return 0;
}
`
