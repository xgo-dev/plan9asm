//go:build go1.27 && linux && amd64

package plan9asm

import (
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestCrossLinuxRuntimeMatrixX86SDK386ABI0SharedTail(t *testing.T) {
	const triple = "i386-unknown-linux-gnu"
	llc := findLLVM22Tool("llc")
	cc, err := exec.LookPath("i686-linux-gnu-gcc")
	if llc == "" || err != nil {
		t.Fatalf("required LLVM22/i386 native tools: llc=%q gcc=%v", llc, err)
	}
	ctx, request := sdkASMDataRequest(t, "386", "crypto/internal/fips140/bigmod")
	ir := func() string {
		llvmCtx := llvm.NewContext()
		defer llvmCtx.Dispose()
		result, err := TranslateGoX86SDKABI0TailModuleInContext(ctx, llvmCtx, request, GoModuleOptions{
			FileName: filepath.Join(request.Directory, "nat_386.s"), GOOS: "linux", GOARCH: "386", TargetTriple: triple,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer result.Module.Dispose()
		return result.Module.String()
	}()
	execution := x86FloatCompareExecution{llc: llc, triple: triple, compiler: []string{cc, "-static", "-no-pie"}}
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			got := execution.compileAndRunLLVM(t, "shared-abi0-tail", ir, sdk386SharedTailDriver, level)
			if string(got) != "24 i386 typed and physical ABI0 results\n" {
				t.Fatalf("incomplete i386 ABI0 execution: %s", got)
			}
		})
	}
}

const sdk386SharedTailDriver = `#include <stdint.h>
#include <stdio.h>

typedef uint32_t word;
typedef word (*multiply)(word *, word *, word);

extern word mul1024(word *, word *, word) __asm__("\"crypto/internal/fips140/bigmod.addMulVVW1024\"");
extern word mul1536(word *, word *, word) __asm__("\"crypto/internal/fips140/bigmod.addMulVVW1536\"");
extern word mul2048(word *, word *, word) __asm__("\"crypto/internal/fips140/bigmod.addMulVVW2048\"");

// This C object crosses the native ABI0 boundary independently of the LLVM
// wrappers. EBX carries the count; the Go frame holds three arguments and carry.
extern word physical_entry(word *, word *, word, word);
__asm__(".text\n.type physical_entry,@function\nphysical_entry:\n"
        "pushl %ebp\n pushl %ebx\n pushl %esi\n pushl %edi\n"
        "movl 32(%esp),%ebx\n subl $16,%esp\n"
        "movl 36(%esp),%eax\n movl %eax,0(%esp)\n"
        "movl 40(%esp),%eax\n movl %eax,4(%esp)\n"
        "movl 44(%esp),%eax\n movl %eax,8(%esp)\n"
        "call addMulVVWx\n movl 12(%esp),%eax\n addl $16,%esp\n"
        "popl %edi\n popl %esi\n popl %ebx\n popl %ebp\n ret\n"
        ".size physical_entry,.-physical_entry\n");

int main(void) {
    const multiply wrappers[] = {mul1024, mul1536, mul2048};
    const word factors[] = {0, 1, 3, UINT32_MAX};
    unsigned checks = 0;
    for (unsigned row = 0; row < 3; row++) {
        const unsigned words = 32 + row * 16;
        for (unsigned factor = 0; factor < 4; factor++) {
            for (unsigned physical = 0; physical < 2; physical++) {
                word dst[66], src[66], want[66], carry = 0;
                for (unsigned i = 0; i < words + 2; i++) {
                    dst[i] = want[i] = UINT32_MAX - 7 * i;
                    src[i] = UINT32_MAX - 5 * i;
                }
                for (unsigned i = 1; i <= words; i++) {
                    uint64_t sum = (uint64_t)src[i] * factors[factor] + want[i] + carry;
                    want[i] = (word)sum;
                    carry = (word)(sum >> 32);
                }
                word got = physical ? physical_entry(dst + 1, src + 1, factors[factor], words)
                                    : wrappers[row](dst + 1, src + 1, factors[factor]);
                if (got != carry)
                    return 1;
                for (unsigned i = 0; i < words + 2; i++)
                    if (dst[i] != want[i])
                        return 2;
                checks++;
            }
        }
    }
    printf("%u i386 typed and physical ABI0 results\n", checks);
    return 0;
}
`
