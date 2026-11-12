package plan9asm

import (
	"os"
	"path/filepath"
	"testing"
)

// This required native owner is never registered on a Windows/macOS host.
// Objects from those hosts cannot substitute for original Go execution.
func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalVEX(t *testing.T) {
	fixedLocalVEXRuntime(t, fixedLocalVEXNativeTools(t), true)
	x87IA32RequireNativeHost(t)
}

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalShuffle(t *testing.T) {
	kernels := fixedLocalShuffleRuntimeKernels()
	if len(kernels) != 41 {
		t.Fatal("legacy and VEX shuffle runtime inventory changed", len(kernels))
	}
	fixedLocalVectorRuntime(t, fixedLocalVEXNativeTools(t), true, kernels)
	x87IA32RequireNativeHost(t)
}

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalShift(t *testing.T) {
	fixedLocalVectorRuntime(t, fixedLocalVEXNativeTools(t), true, fixedLocalShiftRuntimeKernels(t))
	x87IA32RequireNativeHost(t)
}

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalScalarLane(t *testing.T) {
	fixedLocalVectorRuntime(t, fixedLocalVEXNativeTools(t), true, fixedLocalScalarLaneRuntimeKernels(t))
	x87IA32RequireNativeHost(t)
}

func fixedLocalVEXNativeTools(t *testing.T) x86FloatCompareExecution {
	t.Helper()
	x87IA32RequireNativeHost(t)
	execution := x86FloatCompareExecutionTools(t)
	if len(execution.prefix) != 0 || execution.preserveArgv0 {
		t.Fatal("fixed-frame VEX differential execution requires native AMD64")
	}
	directory := t.TempDir()
	source, executable := filepath.Join(directory, "avx2.c"), filepath.Join(directory, "avx2")
	const preflight = `#include <stdio.h>
__attribute__((target("avx2"))) static int original_avx2(void) {
    unsigned bits;
    __asm__ volatile("vpcmpeqb %%ymm0,%%ymm0,%%ymm0; "
                     "vpmovmskb %%ymm0,%0; vzeroupper"
                     : "=r"(bits) :: "ymm0");
    return bits==0xffffffffu;
}
int main(void) {
    __builtin_cpu_init();
    int avx=!!__builtin_cpu_supports("avx");
    int avx2=!!__builtin_cpu_supports("avx2");
    printf("fixed-frame native AVX=%d AVX2=%d\n",avx,avx2);
    return avx && avx2 && original_avx2() ? 0 : 1;
}
`
	if err := os.WriteFile(source, []byte(preflight), 0600); err != nil {
		t.Fatal(err)
	}
	execution.compileC(t, source, executable)
	t.Logf("%s", execution.run(t, executable))
	return execution
}
