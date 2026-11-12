package plan9asm

import (
	"fmt"
	"math"
	"runtime"
	"strings"
	"testing"
)

func TestARM64PoolAffineIntervalImages(t *testing.T) {
	for _, test := range []struct {
		input arm64PoolInterval
		scale int64
		delta uint64
		want  arm64PoolInterval
	}{
		{arm64PoolInterval{math.MaxUint64 - 14, math.MaxUint64}, 1, 16, arm64PoolInterval{1, 15}},
		{arm64PoolInterval{math.MaxUint64 - 14, math.MaxUint64}, 8, 128, arm64PoolInterval{8, 120}},
		{arm64PoolInterval{1, 15}, -1, 16, arm64PoolInterval{1, 15}},
		{arm64PoolInterval{0, 16}, -1, 8, arm64PoolUnknownInterval},
		{arm64PoolInterval{0, math.MaxUint64}, 2, 0, arm64PoolUnknownInterval},
		{arm64PoolUnknownInterval, 0, 42, arm64PoolInterval{42, 42}},
	} {
		if got := arm64PoolIntervalImage(test.input, test.scale, test.delta); got != test.want {
			t.Fatalf("image(%+v, %d, %d)=%+v, want %+v", test.input, test.scale, test.delta, got, test.want)
		}
	}
	// Check represented images against concrete modular arithmetic, including
	// negative and near-wrap inputs. Unknown is conservative, never a mismatch.
	for _, base := range []uint64{0, 31, 1 << 63, math.MaxUint64 - 31} {
		for width := uint64(0); width < 16; width++ {
			for scale := int64(-8); scale <= 8; scale++ {
				for _, delta := range []uint64{0, 7, 128, math.MaxUint64 - 7} {
					span := arm64PoolIntervalImage(arm64PoolInterval{base, base + width}, scale, delta)
					for n := uint64(0); n <= width; n++ {
						value := (base+n)*uint64(scale) + delta
						if value < span.low || value > span.high {
							t.Fatalf("image excludes %d: base=%d width=%d scale=%d delta=%d span=%+v", value, base, width, scale, delta, span)
						}
					}
				}
			}
		}
	}
}

func TestARM64PoolMaskIntervals(t *testing.T) {
	for _, base := range []uint64{0, 8, 16, 1 << 63, math.MaxUint64 - 31} {
		for width := uint64(0); width < 16; width++ {
			for _, mask := range []uint64{0, 1, 7, 16, 24, 0xff, math.MaxUint64, math.MaxUint64 - 7} {
				span := arm64PoolMaskInterval(arm64PoolInterval{base, base + width}, mask)
				for n := uint64(0); n <= width; n++ {
					value := (base + n) & mask
					if value < span.low || value > span.high {
						t.Fatalf("mask excludes %d: base=%d width=%d mask=%x span=%+v", value, base, width, mask, span)
					}
				}
			}
		}
	}
	if got := arm64PoolMaskInterval(arm64PoolInterval{8, 15}, 24); got != (arm64PoolInterval{8, 8}) {
		t.Fatalf("guarded mask: %+v", got)
	}
	if got := arm64PoolMaskInterval(arm64PoolInterval{8, 19}, 24); got != (arm64PoolInterval{8, 16}) {
		t.Fatalf("mask crossing a power-of-two boundary: %+v", got)
	}
	for low := uint64(0); low < 32; low++ {
		for high := low; high < 32; high++ {
			for mask := uint64(0); mask < 32; mask++ {
				want := arm64PoolInterval{math.MaxUint64, 0}
				for value := low; value <= high; value++ {
					masked := value & mask
					if masked < want.low {
						want.low = masked
					}
					if masked > want.high {
						want.high = masked
					}
				}
				if got := arm64PoolMaskInterval(arm64PoolInterval{low, high}, mask); got != want {
					t.Fatalf("[%d,%d] & %d = %+v, want %+v", low, high, mask, got, want)
				}
			}
		}
	}
}

func arm64RawPoolAffineIR(t *testing.T, triple string) string {
	t.Helper()
	lines := []string{
		"adr x9, #0",
		"sub x3, x1, x2", "sub x4, x3, #16", "cmn x4, #15", "orr x8, x1, x1", "b.lo #16",
		"sub x5, x1, x2", "ldrb w5, [x9, x5]", "str x5, [x0]",
		"cmp x3, #3", "b.hi #20", "lsl x6, x1, #2", "sub x6, x6, x2, lsl #2",
		"ldr w6, [x9, x6]", "str x6, [x0, #8]",
		"cmp x3, #8", "b.lo #28", "cmp x3, #15", "b.hi #20",
		"and x7, x3, #24", "sub x7, x7, #8", "ldr q0, [x9, x7]", "str q0, [x0, #16]",
		"sub x10, x9, x1, lsl #3", "add x10, x10, x1, lsl #3", "ldr w10, [x10]", "str x10, [x0, #32]",
		"mov x11, x9", "cbz x2, #8", "add x11, x11, #8", "ldr x11, [x11]", "str x11, [x0, #40]",
		"ldr x1, [x0, #48]", "ldr x2, [x0, #56]", "sub x3, x2, x1", "cmp x3, #1", "b.hi #20",
		"sub x10, x9, x1, lsl #3", "add x10, x10, x2, lsl #3", "ldr x10, [x10]", "str x10, [x0, #64]",
		"cmp x3, #15", "b.ls #20", "cmp x3, #19", "b.hi #20", "tbnz w3, #3, #8", "b #12",
		"ldrb w4, [x9, x3]", "str x4, [x0, #72]",
		"cmp x3, #8", "b.lo #32", "cmp x3, #9", "b.hi #24",
		"sub x10, x9, x1, lsl #3", "add x10, x10, x2, lsl #3", "sub x10, x10, #64",
		"ldr x10, [x10]", "str x10, [x0, #80]",
		"cmp x1, x2", "orr x8, x1, x1", "b.ne #16",
		"sub x10, x2, x1", "ldr q0, [x9, x10]", "str q0, [x0, #88]",
		"cmn x1, x2", "orr x8, x1, x1", "b.ne #16",
		"add x10, x1, x2", "ldr q0, [x9, x10]", "str q0, [x0, #104]",
		"mov x9, xzr", "ret",
	}
	lines[0] = fmt.Sprintf("adr x9, #%d", len(lines)*4)
	var source strings.Builder
	source.WriteString("TEXT pool_affine(SB),$0-24\nMOVD out+0(FP),R0\nMOVD end+8(FP),R1\nMOVD start+16(FP),R2\n")
	for _, word := range assembleARM64LLVMWords(t, lines, "") {
		fmt.Fprintf(&source, "WORD $%#08x\n", word)
	}
	for i := 0; i < 4; i++ {
		fmt.Fprintf(&source, "WORD $%#08x\n", uint32(0x17b4a140+i))
	}
	source.WriteString("RET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"pool_affine": {
			Name: "pool_affine", Args: []LLVMType{Ptr, I64, I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: I64, Index: 1, Field: -1},
				{Offset: 16, Type: I64, Index: 2, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return ir
}

func TestARM64RawPoolAffineLLVM(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir := arm64RawPoolAffineIR(t, triple)
			compileLLVMToObject(t, llc, triple, "pool_affine.ll", "pool_affine.o", ir)
			if runtime.GOARCH == "arm64" && runtime.GOOS == "darwin" && triple == "aarch64-apple-darwin" {
				clang := findLLVM22Tool("clang")
				if clang == "" {
					t.Fatal("LLVM 22 clang not found")
				}
				compileAndRunRuntimeTestForTarget(t, llc, clang, "pool_affine", triple, ir, arm64RawPoolAffineMain, nil)
			}
		})
	}
}

const arm64RawPoolAffineMain = `
#include <stdint.h>
#include <string.h>
extern void pool_affine(uint64_t *, uint64_t, uint64_t);
int main(void) {
  const uint32_t words[4] = {0x17b4a140, 0x17b4a141, 0x17b4a142, 0x17b4a143};
  uint8_t bytes[16];
  memcpy(bytes, words, sizeof(bytes));
  const uint64_t starts[] = {0, 31, 1ULL << 63, UINT64_MAX - 7};
  const uint64_t lengths[] = {0, 1, 2, 3, 4, 8, 9, 10, 13, 14, 15, 16, 17, 18, 19, 20, 255,
                              1ULL << 32, 1ULL << 63, UINT64_MAX};
  for (unsigned i = 0; i < sizeof(starts) / sizeof(starts[0]); i++) {
    for (unsigned j = 0; j < sizeof(lengths) / sizeof(lengths[0]); j++) {
      uint64_t n = lengths[j];
      uint64_t result[17] = {0};
      result[0] = 0x1234;
      result[16] = 0x5678;
      result[7] = starts[i];
      result[8] = starts[i] + n;
      pool_affine(result + 1, starts[i] + n, starts[i]);
      uint64_t expected[2] = {0, 0};
      if (n >= 8 && n <= 15) memcpy(expected, words, sizeof(words));
      uint64_t joined;
      memcpy(&joined, words + (starts[i] != 0 ? 2 : 0), sizeof(joined));
      uint64_t loaded = 0;
      if (n <= 1) memcpy(&loaded, words + n * 2, sizeof(loaded));
      uint64_t negative = 0;
      if (n >= 8 && n <= 9) memcpy(&negative, words + (n - 8) * 2, sizeof(negative));
      uint64_t equal[2] = {0, 0}, zero_sum[2] = {0, 0};
      if (n == 0) memcpy(equal, words, sizeof(words));
      if (starts[i] + starts[i] + n == 0) memcpy(zero_sum, words, sizeof(words));
      if (result[0] != 0x1234 || result[16] != 0x5678 ||
          result[1] != (n >= 1 && n <= 15 ? bytes[n] : 0) ||
          result[2] != (n <= 3 ? words[n] : 0) ||
          result[3] != expected[0] || result[4] != expected[1] ||
          result[5] != words[0] || result[6] != joined ||
          result[7] != starts[i] || result[8] != starts[i] + n || result[9] != loaded ||
          result[10] != (n <= 15 ? bytes[n] : 0) || result[11] != negative ||
          result[12] != equal[0] || result[13] != equal[1] ||
          result[14] != zero_sum[0] || result[15] != zero_sum[1]) return 1;
    }
  }
  return 0;
}
`
