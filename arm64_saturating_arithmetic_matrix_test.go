package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type arm64SaturatingArithmeticSample struct {
	assembly string
	bits     int
	named    string // A Go spelling whose numerical result is deliberately dead.
}

func arm64SaturatingArithmeticSamples() []arm64SaturatingArithmeticSample {
	var samples []arm64SaturatingArithmeticSample
	for i, bank := range "bhsd" {
		bits := 8 << i
		for view, lanes := range []int{1, 64 / bits, 128 / bits} {
			if view == 1 && lanes == 1 {
				continue // There is no D1 vector.
			}
			destination, first, second := string(bank)+"0", string(bank)+"1", string(bank)+"2"
			if lanes > 1 {
				layout := fmt.Sprintf(".%d%c", lanes, bank)
				destination, first, second = "v0"+layout, "v1"+layout, "v2"+layout
			}
			for _, op := range []string{"sqadd", "uqadd", "sqsub", "uqsub"} {
				samples = append(samples, arm64SaturatingArithmeticSample{
					assembly: fmt.Sprintf("%s %s, %s, %s", op, destination, first, second), bits: bits,
				})
			}
			for _, op := range []string{"sqabs", "sqneg", "suqadd", "usqadd"} {
				samples = append(samples, arm64SaturatingArithmeticSample{
					assembly: fmt.Sprintf("%s %s, %s", op, destination, first), bits: bits,
				})
			}
		}
	}
	return samples
}

func assembleARM64SaturatingArithmetic(t *testing.T, samples []arm64SaturatingArithmeticSample) []uint32 {
	t.Helper()
	lines := make([]string, len(samples))
	for i, sample := range samples {
		lines[i] = sample.assembly
	}
	return assembleARM64LLVMWords(t, lines, "")
}

func TestARM64SaturatingArithmeticLLVMMatrix(t *testing.T) {
	samples := arm64SaturatingArithmeticSamples()
	words := assembleARM64SaturatingArithmetic(t, samples)
	if len(words) != 88 {
		t.Fatalf("got %d formats, want all 88", len(words))
	}
	var source strings.Builder
	source.WriteString("TEXT satMatrix(SB),4,$0-0\n")
	for i, word := range words {
		line := fmt.Sprintf("WORD $%#08x", word)
		ins := Instr{Op: OpWORD, Raw: line, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}}
		if err := ProbeInstruction(ArchARM64, "arm64", ins); err != nil {
			t.Errorf("%s: %v", samples[i].assembly, err)
		}
		fmt.Fprintln(&source, line)
	}
	source.WriteString("RET\n")
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
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"satMatrix": {Name: "satMatrix", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Count(ir, `<16 x i8> asm sideeffect`); got != len(words) {
				t.Fatalf("got %d native saturating instructions, want %d", got, len(words))
			}
			compileLLVMToObject(t, llc, triple, "sat-matrix.ll", "sat-matrix.o", ir)
		})
	}
}

func TestCrossLinuxRuntimeMatrixARM64SaturatingArithmeticQC(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	samples := append(arm64SaturatingArithmeticSamples(),
		arm64SaturatingArithmeticSample{assembly: "sqsub v0.4s, v1.4s, v0.4s", bits: 32},
		arm64SaturatingArithmeticSample{assembly: "usqadd d0, d0", bits: 64},
		arm64SaturatingArithmeticSample{assembly: "sqadd v0.16b, v1.16b, v2.16b", bits: 8,
			named: "VSQADD V2.B16, V1.B16, V0.B16"},
		arm64SaturatingArithmeticSample{assembly: "sqabs v0.8h, v1.8h", bits: 16,
			named: "VSQABS V1.H8, V0.H8"},
	)
	words := assembleARM64SaturatingArithmetic(t, samples)
	var source, driver, checks strings.Builder
	driver.WriteString(`
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef void (*sat_fn)(const void *, void *);
static int check(sat_fn translate, sat_fn original, const char *instruction,
                 unsigned bits, int live) {
  uint64_t sign = UINT64_C(1) << (bits - 1);
  uint64_t values[] = {0, 1, sign - 1, sign, sign | 1, sign | (sign - 1)};
  for (unsigned seed = 0; seed < 2; ++seed) {
    for (unsigned row = 0; row < 36; ++row) {
      uint64_t input[7], got[3] = {0}, want[3] = {0};
      unsigned char *lanes = (unsigned char *)input;
      unsigned bytes = bits / 8;
      for (unsigned i = 0; i < 16; i += bytes) {
        unsigned lane = i / bytes;
        memcpy(lanes + i, &values[(row % 6 + lane) % 6], bytes);
        memcpy(lanes + 16 + i, &values[(row / 6 + lane) % 6], bytes);
        memcpy(lanes + 32 + i, &values[(row % 6 + lane) % 6], bytes);
      }
      input[6] = seed ? UINT64_C(0x8000000) : 0;
      original(input, want);
      translate(input, got);
      if (got[2] != want[2] || (live && memcmp(got, want, 16))) {
        fprintf(stderr, "%s row %u seed %u: FPSR=%llx want %llx, result match=%d\n",
                instruction, row, seed, (unsigned long long)got[2],
                (unsigned long long)want[2], !memcmp(got, want, 16));
        return 1;
      }
    }
  }
  return 0;
}
`)
	sigs := make(map[string]FuncSig)
	for i, sample := range samples {
		name := fmt.Sprintf("nativeSat%d", i)
		fmt.Fprintf(&source, `TEXT %s(SB),4,$0-16
MOVD input+0(FP), R0
MOVD out+8(FP), R1
MRS FPSR, R10
MOVD 48(R0), R11
MSR R11, FPSR
VLD1 (R0), [V0.B16, V1.B16, V2.B16]
`, name)
		live := 1
		if sample.named != "" {
			fmt.Fprintln(&source, sample.named)
			live = 0
		} else {
			fmt.Fprintf(&source, "WORD $%#08x\nVST1 [V0.B16], (R1)\n", words[i])
		}
		source.WriteString("MRS FPSR, R11\nMSR R10, FPSR\nMOVD R11, 16(R1)\nRET\n")
		sigs[name] = sigWithClassicFrame(name, []LLVMType{Ptr, Ptr}, Void)
		fmt.Fprintf(&driver, `extern void %[1]s(const void *, void *);
static void original%[2]d(const void *input, void *output) {
  uint64_t old, status, seed = ((const uint64_t *)input)[6];
  __asm__ volatile("mrs %%0, fpsr\nmsr fpsr, %%4\n"
                   "ld1 {v0.16b, v1.16b, v2.16b}, [%%2]\n"
                   ".inst %#[3]x\nst1 {v0.16b}, [%%3]\n"
                   "mrs %%1, fpsr\nmsr fpsr, %%0"
                  : "=&r"(old), "=&r"(status) : "r"(input), "r"(output), "r"(seed)
                  : "v0", "v1", "v2", "memory");
  ((uint64_t *)output)[2] = status;
}
`, name, i, words[i])
		fmt.Fprintf(&checks, "  if (check(%s, original%d, %q, %d, %d)) return 1;\n",
			name, i, sample.assembly, sample.bits, live)
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
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "arm64_sat_arithmetic",
				triple, input, driver.String(), runner, opt)
		})
	}
}
