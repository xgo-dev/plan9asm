package plan9asm

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Observation only: no ISA permission or substitute numerical verdict.
func TestX86FloatingCompareActualExecutionISAAudit(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	directory := t.TempDir()
	source := filepath.Join(directory, "isa.c")
	executable := filepath.Join(directory, "isa")
	const program = `#include <stdint.h>
#include <stdio.h>
#include <cpuid.h>
int main(void) {
    unsigned a, b, c, d;
    uint64_t xcr0 = 0;
    unsigned osxsave = 0, raw_avx = 0, raw_f = 0, raw_vl = 0;
    if (__get_cpuid(1, &a, &b, &c, &d)) {
        osxsave = (c >> 27) & 1;
        raw_avx = (c >> 28) & 1;
        if (osxsave) {
            unsigned low, high;
            __asm__ volatile("xgetbv" : "=a"(low), "=d"(high) : "c"(0));
            xcr0 = ((uint64_t)high << 32) | low;
        }
    }
    if (__get_cpuid_count(7, 0, &a, &b, &c, &d)) {
        raw_f = (b >> 16) & 1;
        raw_vl = (b >> 31) & 1;
    }
    __builtin_cpu_init();
    printf("SSE2=%d AVX=%d AVX2=%d AVX512F=%d AVX512VL=%d "
           "rawAVX=%u rawAVX512F=%u rawAVX512VL=%u OSXSAVE=%u XCR0=%llx\n",
           !!__builtin_cpu_supports("sse2"), !!__builtin_cpu_supports("avx"),
           !!__builtin_cpu_supports("avx2"), !!__builtin_cpu_supports("avx512f"),
           !!__builtin_cpu_supports("avx512vl"), raw_avx, raw_f, raw_vl,
           osxsave, (unsigned long long)xcr0);
    return 0;
}
`
	if err := os.WriteFile(source, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	execution.compileC(t, source, executable)
	output := execution.run(t, executable)
	t.Logf("actual execution host=%s/%s triple=%s prefix=%q: %s",
		runtime.GOOS, runtime.GOARCH, execution.triple, execution.prefix, output)
}
