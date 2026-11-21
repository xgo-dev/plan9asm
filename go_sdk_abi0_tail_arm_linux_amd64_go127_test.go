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
	testCrossLinuxRuntimeSDKARMSharedTail(t, "arm64", llc, triple, compiler, runner, sdkARM64ABIBridge)
}

func TestCrossLinuxRuntimeMatrixARMSDKABI0SharedTail(t *testing.T) {
	testCrossLinuxRuntimeSDKARMSharedTail(t, "arm", requireARMScalarRuntime(t), "armv7-unknown-linux-gnueabihf",
		[]string{"arm-linux-gnueabihf-gcc"}, []string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"}, sdkARMABIBridge)
}

func testCrossLinuxRuntimeSDKARMSharedTail(t *testing.T, arch, llc, triple string, compiler, runner []string, bridge string) {
	t.Helper()
	ctx, request := sdkASMDataRequest(t, arch, "crypto/internal/fips140/bigmod")
	member := filepath.Join(request.Directory, "nat_"+arch+".s")
	t.Run("original Go", func(t *testing.T) {
		source, err := os.ReadFile(member)
		if err != nil {
			t.Fatal(err)
		}
		if arch == "arm" {
			runARMGoSourceOracle(t, string(source), sdkARMSharedTailOriginal)
		} else {
			runARM64LocalRegisterGoOracle(t, string(source), sdkARMSharedTailOriginal, len(runner) != 0)
		}
	})
	ir := func() string {
		llvmCtx := llvm.NewContext()
		defer llvmCtx.Dispose()
		translate := TranslateGoARM64SDKABI0TailModuleInContext
		if arch == "arm" {
			translate = TranslateGoARMSDKABI0TailModuleInContext
		}
		result, err := translate(ctx, llvmCtx, request, GoModuleOptions{
			FileName: member, GOOS: "linux", GOARCH: arch, TargetTriple: triple,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer result.Module.Dispose()
		return result.Module.String()
	}()
	for _, level := range []int{0, 2} {
		t.Run(fmt.Sprintf("LLVM/O%d", level), func(t *testing.T) {
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "sdk_abi0_shared_tail_"+arch, triple,
				ir, sdkARMSharedTailDriver+bridge, runner, level)
		})
	}
}

const sdkARMSharedTailOriginal = `package main
import "math/bits"

func addMulVVW1024(z, x *uint, y uint) (c uint)
func addMulVVW1536(z, x *uint, y uint) (c uint)
func addMulVVW2048(z, x *uint, y uint) (c uint)

func main() {
	for row, multiply := range [...]func(*uint, *uint, uint) uint{addMulVVW1024, addMulVVW1536, addMulVVW2048} {
		words := (1024 + 512*row) / bits.UintSize
		for _, factor := range [...]uint{0, 1, 3, ^uint(0)} {
			var dst, src, want [66]uint
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

const sdkARMSharedTailDriver = `#include <stdint.h>
#include <limits.h>

typedef uintptr_t word;
#if UINTPTR_MAX == UINT32_MAX
typedef uint64_t double_word;
#else
typedef __uint128_t double_word;
#endif
typedef word (*multiply)(word *, word *, word);

extern word mul1024(word *, word *, word) __asm__("\"crypto/internal/fips140/bigmod.addMulVVW1024\"");
extern word mul1536(word *, word *, word) __asm__("\"crypto/internal/fips140/bigmod.addMulVVW1536\"");
extern word mul2048(word *, word *, word) __asm__("\"crypto/internal/fips140/bigmod.addMulVVW2048\"");

extern word physical_entry(word *, word *, word, word);

int main(void) {
	const unsigned word_bits = sizeof(word) * CHAR_BIT;
	const multiply wrappers[] = {mul1024, mul1536, mul2048};
	const word factors[] = {0, 1, 3, UINTPTR_MAX};
	for (unsigned row = 0; row < 3; row++) {
		const unsigned words = (1024 + row * 512) / word_bits;
		for (unsigned factor = 0; factor < 4; factor++) {
			for (unsigned physical = 0; physical < 2; physical++) {
				word dst[66], src[66], want[66], carry = 0;
				for (unsigned i = 0; i < words + 2; i++) {
					dst[i] = want[i] = UINTPTR_MAX - 7 * i;
					src[i] = UINTPTR_MAX - 5 * i;
				}
				for (unsigned i = 1; i <= words; i++) {
					double_word sum = (double_word)src[i] * factors[factor] + want[i] + carry;
					want[i] = (word)sum;
					carry = (word)(sum >> word_bits);
				}
				word got = physical ? physical_entry(dst + 1, src + 1, factors[factor], words)
				                    : wrappers[row](dst + 1, src + 1, factors[factor]);
				if (got != carry) return 1;
				for (unsigned i = 0; i < words + 2; i++) {
					if (dst[i] != want[i] || src[i] != UINTPTR_MAX - 5 * i) return 2;
				}
			}
		}
	}
	return 0;
}
`

// The AArch64 Go entry uses R0 for the count and FP for the ABI0 frame.
const sdkARM64ABIBridge = `
__asm__(".text\n.p2align 2\n.type physical_entry,%function\nphysical_entry:\n"
        "stp x19,x20,[sp,#-32]!\n stp x21,x30,[sp,#16]\n"
        "sub sp,sp,#48\n stp x0,x1,[sp,#8]\n str x2,[sp,#24]\n"
        "mov x0,x3\n bl addMulVVWx\n ldr x0,[sp,#32]\n add sp,sp,#48\n"
        "ldp x21,x30,[sp,#16]\n ldp x19,x20,[sp],#32\n ret\n"
        ".size physical_entry,.-physical_entry\n");
`

// The A32 Go entry uses R5 and a different caller frame offset and word size.
const sdkARMABIBridge = `
__asm__(".text\n.arm\n.p2align 2\n.type physical_entry,%function\nphysical_entry:\n"
        "push {r4,r5,r6,r7,r8,lr}\n sub sp,sp,#24\n"
        "str r0,[sp,#4]\n str r1,[sp,#8]\n str r2,[sp,#12]\n"
        "mov r5,r3\n bl addMulVVWx\n ldr r0,[sp,#16]\n add sp,sp,#24\n"
        "pop {r4,r5,r6,r7,r8,pc}\n.size physical_entry,.-physical_entry\n");
`
