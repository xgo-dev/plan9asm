package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixARM64FloatNarrowStatus(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	cases := []struct {
		instruction string
		sourceBits  int
		destination int
		dead        bool
		named       string
	}{
		{instruction: "fcvtn v0.4h, v1.4s", sourceBits: 32},
		{instruction: "fcvtn2 v0.8h, v1.4s", sourceBits: 32},
		{instruction: "fcvtn v0.2s, v1.2d", sourceBits: 64},
		{instruction: "fcvtn2 v0.4s, v1.2d", sourceBits: 64},
		{instruction: "fcvtxn s0, d1", sourceBits: 64},
		{instruction: "fcvtxn v0.2s, v1.2d", sourceBits: 64},
		{instruction: "fcvtxn2 v0.4s, v1.2d", sourceBits: 64},
		{instruction: "fcvtn2 v1.8h, v1.4s", sourceBits: 32, destination: 1},
		{instruction: "fcvtxn2 v1.4s, v1.2d", sourceBits: 64, destination: 1},
		{instruction: "fcvtxn s1, d1", sourceBits: 64, destination: 1},
		{instruction: "fcvtn v0.2s, v1.2d", sourceBits: 64, dead: true, named: "VFCVTN V1.D2, V0.S2"},
		{instruction: "fcvtxn s0, d1", sourceBits: 64, dead: true},
	}
	instructions := make([]string, len(cases))
	for i, sample := range cases {
		instructions[i] = sample.instruction
	}
	words := assembleARM64LLVMWords(t, instructions, "")
	var source, driver, checks strings.Builder
	driver.WriteString(`
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef void (*narrow_fn)(const void *, void *);
static int check(narrow_fn translate, narrow_fn original, const char *instruction,
                 unsigned source_bits, int dead) {
  static const uint64_t fpcr_values[] = {
    0, 1u << 22, 2u << 22, 3u << 22, 1u << 19, 1u << 24, 1u << 25, 1u << 26,
    1u << 2, (1u << 2) | (1u << 1),
  };
  static const uint32_t single_values[14] = {
    0, 0x80000000, 0x3f800001, 0xbf800001, 0x3f801000, 0x33000000, 1,
    0x477fe000, 0x47800000, 0x7f800000, 0xff800000, 0x7fc01234, 0x7f801234, 0x3f800000,
  };
  static const uint64_t double_values[14] = {
    0, 0x8000000000000000ULL, 0x3ff0000000000001ULL, 0xbff0000000000001ULL,
    0x3ff0000010000000ULL, 0x3690000000000000ULL, 1, 0x47efffffe0000000ULL,
    0x47f0000000000000ULL, 0x7ff0000000000000ULL, 0xfff0000000000000ULL,
    0x7ff8020000001234ULL, 0x7ff0020000001234ULL, 0x3ff0000000000000ULL,
  };
  unsigned lanes = 128 / source_bits;
  unsigned bytes = source_bits / 8;
  for (unsigned mode = 0; mode < sizeof(fpcr_values)/sizeof(fpcr_values[0]); ++mode) {
    for (unsigned row = 0; row < 14; ++row) {
      uint64_t input[6] = {0x123456789abcdef0ULL, 0x0fedcba987654321ULL};
      unsigned char *values = (unsigned char *)(input + 2);
      uint64_t got[3] = {0}, want[3] = {0};
      for (unsigned lane = 0; lane < lanes; ++lane) {
        unsigned index = (row + lane) % 14;
        const void *value = source_bits == 32 ? (const void *)&single_values[index] :
                                               (const void *)&double_values[index];
        memcpy(values + lane * bytes, value, bytes);
      }
      input[4] = fpcr_values[mode];
      input[5] = row & 1 ? UINT64_C(0x8000000) : 0;
      original(input, want);
      translate(input, got);
      if (got[2] != want[2] || (!dead && memcmp(got, want, 16))) {
        fprintf(stderr, "%s mode %u row %u: FPSR=%llx want %llx, same result=%d\n",
                instruction, mode, row, (unsigned long long)got[2],
                (unsigned long long)want[2], !memcmp(got, want, 16));
        return 1;
      }
    }
  }
  return 0;
}
`)
	sigs := make(map[string]FuncSig)
	for i, sample := range cases {
		name := fmt.Sprintf("floatNarrow%d", i)
		fmt.Fprintf(&source, `TEXT %s(SB),4,$0-16
MOVD input+0(FP), R0
MOVD out+8(FP), R1
MRS FPCR, R10
MRS FPSR, R11
MOVD 32(R0), R2
MOVD 40(R0), R3
MSR R2, FPCR
MSR R3, FPSR
VLD1 (R0), [V0.B16, V1.B16]
`, name)
		if sample.named != "" {
			fmt.Fprintln(&source, sample.named)
		} else {
			fmt.Fprintf(&source, "WORD $%#08x\n", words[i])
		}
		dead := 0
		if sample.dead {
			dead = 1
		} else {
			fmt.Fprintf(&source, "VST1 [V%d.B16], (R1)\n", sample.destination)
		}
		source.WriteString("MRS FPSR, R3\nMSR R11, FPSR\nMSR R10, FPCR\nMOVD R3, 16(R1)\nRET\n")
		sigs[name] = sigWithClassicFrame(name, []LLVMType{Ptr, Ptr}, Void)
		fmt.Fprintf(&driver, `extern void %[1]s(const void *, void *);
static void original%[2]d(const void *input, void *output) {
  uint64_t old_control, old_status, status;
  const uint64_t *in = (const uint64_t *)input;
  __asm__ volatile("mrs %%0, fpcr\nmrs %%1, fpsr\n"
                   "msr fpcr, %%5\nmsr fpsr, %%6\n"
                   "ld1 {v0.16b, v1.16b}, [%%3]\n"
                   ".inst %#[3]x\nst1 {v%[4]d.16b}, [%%4]\n"
                   "mrs %%2, fpsr\nmsr fpsr, %%1\nmsr fpcr, %%0"
                   : "=&r"(old_control), "=&r"(old_status), "=&r"(status)
                   : "r"(input), "r"(output), "r"(in[4]), "r"(in[5])
                   : "v0", "v1", "memory");
  ((uint64_t *)output)[2] = status;
}
`, name, i, words[i], sample.destination)
		fmt.Fprintf(&checks, "  if (check(%s, original%d, %q, %d, %d)) return 1;\n",
			name, i, sample.instruction, sample.sourceBits, dead)
	}
	driver.WriteString("int main(void) {\n" + checks.String() + "  return 0;\n}\n")
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	for _, opt := range []int{0, 2} {
		t.Run(fmt.Sprintf("O%d", opt), func(t *testing.T) {
			input := ir
			if opt == 2 {
				input = armFloatEffectOptimizedIR(t, ir)
			}
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "arm64_float_narrow",
				triple, input, driver.String(), runner, opt)
		})
	}
}
