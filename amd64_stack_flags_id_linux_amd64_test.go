package plan9asm

import (
	"os"
	"testing"
)

// This prefix is selected by the exhaustive required Linux cross-runtime job.
// Both originals execute directly: IA32 compilation is not execution evidence.
func TestCrossLinuxRuntimeMatrixX86StackFlagsIDNativeGo(t *testing.T) {
	x87IA32RequireNativeHost(t)
	t.Run("OriginalAMD64", TestX86StackFlagsIDNativeGo)
	t.Run("Original386", func(t *testing.T) {
		original := x86StackIDOriginalExecutable(t, "linux", "386")
		sealed, err := x87IA32StaticExecutable(original)
		if err != nil {
			t.Fatal(err)
		}
		output := x87IA32RunDirect(t, sealed, nil, os.Environ())
		if string(output) != "original Go stack ID observations 4\n" {
			t.Fatalf("strict native original Go IA32 four-word oracle: %q", output)
		}
	})
	x87IA32RequireNativeHost(t)
}

func TestCrossLinuxRuntimeMatrixX86MixedWidthStackOriginalGo(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang required")
	}
	const triple = "x86_64-unknown-linux-gnu"
	execution := x86FloatCompareExecution{
		llc: llc, triple: triple, compiler: []string{clang, "-target", triple},
	}
	const source = `TEXT ·Replace(SB),4,$0-16
	PUSHQ value+0(FP)
	POPW AX
	PUSHW $9
	POPQ DX
	MOVQ DX,ret+8(FP)
	RET
TEXT ·Combine(SB),4,$0-8
	PUSHW $0xa1b2
	PUSHW $0xc3d4
	PUSHW $0xe5f6
	PUSHW $0x0718
	POPQ DX
	MOVQ DX,ret+0(FP)
	RET
`
	const declarations = "func Replace(value uint64) uint64\nfunc Combine() uint64\n"
	const goMain = `
func main() {
	for _, x := range []uint64{0, ^uint64(0), 0xff123456789abcde, 1 << 63} {
		if Replace(x) != x &^ uint64(0xffff) | 9 { panic("replace") }
	}
	if Combine() != 0xa1b2c3d4e5f60718 { panic("combine") }
	fmt.Println("mixed-width private stack values passed")
}
`
	const cMain = `#include <stdint.h>
#include <stdio.h>
extern uint64_t Replace(uint64_t), Combine(void);
int main(void) {
	const uint64_t values[] = {0, UINT64_MAX, UINT64_C(0xff123456789abcde), UINT64_C(1) << 63};
	for (unsigned i = 0; i < sizeof values / sizeof values[0]; ++i) {
		if (Replace(values[i]) != ((values[i] & ~UINT64_C(0xffff)) | 9)) return 1;
	}
	if (Combine() != UINT64_C(0xa1b2c3d4e5f60718)) return 2;
	puts("mixed-width private stack values passed");
	return 0;
}
`
	x86DirectTailCheckCallRuntime(t, "amd64", execution, source, declarations, goMain, cMain,
		"mixed-width private stack values passed\n")
}
