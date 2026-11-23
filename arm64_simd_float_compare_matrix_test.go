package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type arm64SIMDFloatCompareCase struct {
	instruction string
	bits, lanes int
	destination int
}

func arm64SIMDFloatCompareCases() ([]arm64SIMDFloatCompareCase, []string) {
	shapes := []struct {
		bits, lanes int
		bank        string
	}{
		{16, 1, "h"}, {32, 1, "s"}, {64, 1, "d"},
		{16, 4, "h"}, {16, 8, "h"}, {32, 2, "s"}, {32, 4, "s"}, {64, 2, "d"},
	}
	var cases []arm64SIMDFloatCompareCase
	var instructions []string
	for _, shape := range shapes {
		dst, first, second := shape.bank+"0", shape.bank+"1", shape.bank+"2"
		if shape.lanes > 1 {
			layout := fmt.Sprintf(".%d%s", shape.lanes, shape.bank)
			dst, first, second = "v0"+layout, "v1"+layout, "v2"+layout
		}
		for _, op := range []string{"fcmeq", "fcmge", "fcmgt", "fcmle", "fcmlt", "facge", "facgt"} {
			if op != "fcmle" && op != "fcmlt" {
				line := fmt.Sprintf("%s %s, %s, %s", op, dst, first, second)
				instructions = append(instructions, line)
				cases = append(cases, arm64SIMDFloatCompareCase{line, shape.bits, shape.lanes, 0})
			}
			if op != "facge" && op != "facgt" {
				line := fmt.Sprintf("%s %s, %s, #0.0", op, dst, first)
				instructions = append(instructions, line)
				cases = append(cases, arm64SIMDFloatCompareCase{line, shape.bits, shape.lanes, 0})
			}
		}
	}
	return cases, instructions
}

func TestCrossLinuxRuntimeMatrixARM64SIMDFloatCompare(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	cases, instructions := arm64SIMDFloatCompareCases()
	for _, sample := range []arm64SIMDFloatCompareCase{
		{"fcmge h2, h1, h2", 16, 1, 2},
		{"fcmeq s1, s1, s2", 32, 1, 1},
		{"fcmgt v2.2d, v1.2d, v2.2d", 64, 2, 2},
		{"fcmle v1.2s, v1.2s, #0.0", 32, 2, 1},
	} {
		cases = append(cases, sample)
		instructions = append(instructions, sample.instruction)
	}
	words := assembleARM64LLVMWords(t, instructions, "+fullfp16")
	var source, driver, checks strings.Builder
	driver.WriteString(`
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef void (*compare_fn)(const unsigned char *, uint64_t *);

static int check(compare_fn translate, compare_fn original, const char *label,
                 unsigned bytes) {
  static const uint64_t values[3][9] = {
    {0, 0x8000, 0x3c00, 0xc000, 0x7c00, 0xfc00, 0x7e00, 0x7c01, 1},
    {0, 0x80000000, 0x3f800000, 0xc0000000, 0x7f800000, 0xff800000,
     0x7fc00000, 0x7f800001, 1},
    {0, 0x8000000000000000ULL, 0x3ff0000000000000ULL, 0xc000000000000000ULL,
     0x7ff0000000000000ULL, 0xfff0000000000000ULL, 0x7ff8000000000000ULL,
     0x7ff0000000000001ULL, 1},
  };
  const uint64_t *v = values[bytes == 2 ? 0 : bytes == 4 ? 1 : 2];
  for (unsigned pair = 0; pair < 81; ++pair) {
    unsigned char in[32];
    for (unsigned i = 0; i < 16; i += bytes) {
      memcpy(in + i, &v[(pair / 9 + i/bytes) % 9], bytes);
      memcpy(in + 16 + i, &v[(pair % 9 + 2*i/bytes) % 9], bytes);
    }
    uint64_t got[3], want[3];
    original(in, want);
    translate(in, got);
    if (memcmp(want, got, sizeof(want))) {
      fprintf(stderr, "%s input %u: got %llx %llx FPSR=%llx, want %llx %llx FPSR=%llx\n",
              label, pair, (unsigned long long)got[0], (unsigned long long)got[1],
              (unsigned long long)got[2], (unsigned long long)want[0],
              (unsigned long long)want[1], (unsigned long long)want[2]);
      return 1;
    }
  }
  return 0;
}
`)
	sigs := make(map[string]FuncSig)
	for i, sample := range cases {
		name := fmt.Sprintf("compareMask%d", i)
		fmt.Fprintf(&source, `TEXT %s(SB),4,$0-16
MOVD input+0(FP), R0
MOVD out+8(FP), R1
MRS FPSR, R10
MOVD $0x8000000, R11
MSR R11, FPSR
VLD1 (R0), [V1.B16, V2.B16]
WORD $%#08x
VST1 [V%d.B16], (R1)
MRS FPSR, R11
MSR R10, FPSR
MOVD R11, 16(R1)
RET
`, name, words[i], sample.destination)
		sigs[name] = sigWithClassicFrame(name, []LLVMType{Ptr, Ptr}, Void)
		fmt.Fprintf(&driver, `extern void %[1]s(const unsigned char *, uint64_t *);
static void original%[2]d(const unsigned char *in, uint64_t *out) {
  uint64_t old, status, seed = 0x8000000;
  __asm__ volatile("mrs %%0, fpsr\nmsr fpsr, %%4\n"
                   "ld1 {v1.16b, v2.16b}, [%%2]\n"
                   ".inst %#[3]x\nst1 {v%[4]d.16b}, [%%3]\n"
                   "mrs %%1, fpsr\nmsr fpsr, %%0"
                  : "=&r"(old), "=&r"(status) : "r"(in), "r"(out), "r"(seed)
                  : "v0", "v1", "v2", "memory");
  out[2] = status;
}
`, name, i, words[i], sample.destination)
		fmt.Fprintf(&checks, "    if (check(%s, original%d, %q, %d)) return 1;\n",
			name, i, sample.instruction, sample.bits/8)
	}
	driver.WriteString(`
int main(void) {
  uint64_t old;
  __asm__ volatile("mrs %0, fpcr" : "=r"(old));
  for (unsigned mode = 0; mode < 2; ++mode) {
    uint64_t fpcr = mode ? (1u << 24) | (1u << 19) | (1u << 2) : 0;
    __asm__ volatile("msr fpcr, %0" : : "r"(fpcr) : "memory");
`)
	driver.WriteString(checks.String())
	driver.WriteString(`
  }
  __asm__ volatile("msr fpcr, %0" : : "r"(old) : "memory");
  return 0;
}
`)
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
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "arm64_simd_compare",
				triple, input, driver.String(), runner, opt)
		})
	}
}

func TestARM64SIMDFloatCompareLLVMMatrix(t *testing.T) {
	cases, instructions := arm64SIMDFloatCompareCases()
	words := assembleARM64LLVMWords(t, instructions, "+fullfp16")
	if len(words) != 80 {
		t.Fatalf("got %d architecture forms, want 80", len(words))
	}
	var source strings.Builder
	source.WriteString("TEXT compareMask(SB),4,$0-0\n")
	for i, word := range words {
		form, ok := decodeARM64RawFloatCompare(word)
		sample := cases[i]
		if !ok || form.arrangement != (arm64VectorArrangement{sample.bits, sample.lanes}) {
			t.Errorf("%s (%#08x): decode = %+v, %t", sample.instruction, word, form, ok)
		}
		fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{arm64LinuxGNUTriple, "aarch64-apple-darwin", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				Goarch: "arm64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"compareMask": {Name: "compareMask", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Count(ir, `asm sideeffect "f`); got != len(words) {
				t.Fatalf("got %d native comparisons, want %d", got, len(words))
			}
			compileLLVMToObject(t, llc, triple, "simd-compare.ll", "simd-compare.o", ir)
		})
	}
}
