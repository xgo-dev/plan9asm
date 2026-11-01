//go:build linux && amd64

package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86PackedIntegerCompareOriginalNativeWideBits(t *testing.T) {
	// No emulator, Rosetta, host-inapplicable Skip, or object-only substitute.
	// The shared preflight binds native AMD64 and enabled AVX512F/VL state.
	execution := x86FloatCompareRuntimeTools(t, x86FloatCompareEVEX)
	dir := t.TempDir()
	input, output := filepath.Join(dir, "compare-isa.c"), filepath.Join(dir, "compare-isa")
	const program = `#include <cpuid.h>
#include <stdio.h>
#include <sys/resource.h>

int main(void) {
    struct rlimit noCore = {0,0};
    if (setrlimit(RLIMIT_CORE,&noCore)) return 77;
    unsigned a,b,c,d;
    if (!__get_cpuid_count(7,0,&a,&b,&c,&d)) return 78;
    printf("AVX2=%u AVX512BW=%u\n",(b>>5)&1,(b>>30)&1);
    return (b&(1u<<5)) && (b&(1u<<30)) ? 0 : 79;
}
`
	if err := os.WriteFile(input, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	compile := append([]string(nil), execution.compiler...)
	compile = append(compile, "-O2", input, "-o", output)
	x86FloatCompareCaptureCommand(t, exec.Command(compile[0], compile[1:]...))
	run := execution.command(output)
	t.Logf("native packed integer ISA supplement: %s", x86FloatCompareCaptureCommand(t, exec.Command(run[0], run[1:]...)))
	declaration, assembly, tests := x86PackedIntegerCompareOriginalWideSources()
	x86LEAActualTargetGoObject(t, "amd64", execution.triple, assembly)
	x86PackedIntegerCompareRunOriginalGo(t, declaration, assembly, tests)
	t.Log("532 native original Go forms ×48 independent scalar lane/full-bank/K/flags/CSR/full-buffer observations; execution requires native Linux AMD64 AVX2+AVX512F/VL/BW")
}
