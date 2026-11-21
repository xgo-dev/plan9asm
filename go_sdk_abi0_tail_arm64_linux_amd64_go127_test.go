//go:build go1.27 && linux && amd64

package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestCrossLinuxRuntimeMatrixARM64SDKABI0SharedTail(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	ctx, request := sdkASMDataRequest(t, "arm64", "crypto/internal/fips140/bigmod")
	member := filepath.Join(request.Directory, "nat_arm64.s")
	t.Run("original Go", func(t *testing.T) {
		source, err := os.ReadFile(member)
		if err != nil {
			t.Fatal(err)
		}
		runARM64LocalRegisterGoOracle(t, string(source), sdkARM64SharedTailOriginal, len(runner) != 0)
	})
	ir := func() string {
		llvmCtx := llvm.NewContext()
		defer llvmCtx.Dispose()
		result, err := TranslateGoARM64SDKABI0TailModuleInContext(ctx, llvmCtx, request, GoModuleOptions{
			FileName: member, GOOS: "linux", GOARCH: "arm64", TargetTriple: triple,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer result.Module.Dispose()
		return result.Module.String()
	}()
	for _, level := range []int{0, 2} {
		t.Run(fmt.Sprintf("LLVM/O%d", level), func(t *testing.T) {
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "sdk_abi0_shared_tail_arm64", triple,
				ir, sdkARM64SharedTailDriver, runner, level)
		})
	}
}

const sdkARM64SharedTailOriginal = `package main
import "math/bits"

func addMulVVW1024(z, x *uint, y uint) (c uint)
func addMulVVW1536(z, x *uint, y uint) (c uint)
func addMulVVW2048(z, x *uint, y uint) (c uint)

func main() {
	for row, multiply := range [...]func(*uint, *uint, uint) uint{addMulVVW1024, addMulVVW1536, addMulVVW2048} {
		words := 16 + 8*row
		for _, factor := range [...]uint{0, 1, 3, ^uint(0)} {
			var dst, src, want [34]uint
			for i := 0; i < words+2; i++ {
				dst[i], src[i] = ^uint(0)-7*uint(i), ^uint(0)-5*uint(i)
			}
			want, original := dst, src
			var carry uint
			for i := 1; i <= words; i++ {
				hi, lo := bits.Mul(src[i], factor)
				lo, c1 := bits.Add(lo, want[i], 0)
				lo, c2 := bits.Add(lo, carry, 0)
				want[i], carry = lo, hi+c1+c2
			}
			if multiply(&dst[1], &src[1], factor) != carry || dst != want || src != original {
				panic("original SDK ABI0 multiply, carry or memory boundary")
			}
		}
	}
}
`

const sdkARM64SharedTailDriver = `#include <stdint.h>

typedef uint64_t word;
typedef word (*multiply)(word *, word *, word);

extern word mul1024(word *, word *, word) __asm__("\"crypto/internal/fips140/bigmod.addMulVVW1024\"");
extern word mul1536(word *, word *, word) __asm__("\"crypto/internal/fips140/bigmod.addMulVVW1536\"");
extern word mul2048(word *, word *, word) __asm__("\"crypto/internal/fips140/bigmod.addMulVVW2048\"");

// The Go entry uses R0 for the count and FP for the full caller's ABI0 frame.
extern word physical_entry(word *, word *, word, word);
__asm__(".text\n.p2align 2\n.type physical_entry,%function\nphysical_entry:\n"
        "stp x19,x20,[sp,#-32]!\n stp x21,x30,[sp,#16]\n"
        "sub sp,sp,#48\n stp x0,x1,[sp,#8]\n str x2,[sp,#24]\n"
        "mov x0,x3\n bl addMulVVWx\n ldr x0,[sp,#32]\n add sp,sp,#48\n"
        "ldp x21,x30,[sp,#16]\n ldp x19,x20,[sp],#32\n ret\n"
        ".size physical_entry,.-physical_entry\n");

int main(void) {
	const multiply wrappers[] = {mul1024, mul1536, mul2048};
	const word factors[] = {0, 1, 3, UINT64_MAX};
	for (unsigned row = 0; row < 3; row++) {
		const unsigned words = 16 + row * 8;
		for (unsigned factor = 0; factor < 4; factor++) {
			for (unsigned physical = 0; physical < 2; physical++) {
				word dst[34], src[34], want[34], carry = 0;
				for (unsigned i = 0; i < words + 2; i++) {
					dst[i] = want[i] = UINT64_MAX - 7 * i;
					src[i] = UINT64_MAX - 5 * i;
				}
				for (unsigned i = 1; i <= words; i++) {
					__uint128_t sum = (__uint128_t)src[i] * factors[factor] + want[i] + carry;
					want[i] = (word)sum;
					carry = (word)(sum >> 64);
				}
				word got = physical ? physical_entry(dst + 1, src + 1, factors[factor], words)
				                    : wrappers[row](dst + 1, src + 1, factors[factor]);
				if (got != carry) return 1;
				for (unsigned i = 0; i < words + 2; i++) {
					if (dst[i] != want[i] || src[i] != UINT64_MAX - 5 * i) return 2;
				}
			}
		}
	}
	return 0;
}
`
