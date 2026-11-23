package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type arm64NarrowSample struct {
	assembly    string
	bits, shift int
	destination int
	dead        bool
	named       string
}

func arm64NarrowSamples(allShifts bool) []arm64NarrowSample {
	var samples []arm64NarrowSample
	for i, narrow := range "bhs" {
		wide := "hsd"[i]
		bits := 8 << i
		lanes := 64 / bits
		for _, op := range []string{
			"sqxtn", "uqxtn", "sqxtun", "sqshrn", "sqrshrn", "uqshrn", "uqrshrn", "sqshrun", "sqrshrun",
		} {
			shifts := []int{0}
			if strings.Contains(op, "shr") {
				shifts = []int{1, bits}
				if allShifts {
					shifts = make([]int, bits)
					for i := range shifts {
						shifts[i] = i + 1
					}
				}
			}
			for _, shift := range shifts {
				immediate := ""
				if shift != 0 {
					immediate = fmt.Sprintf(", #%d", shift)
				}
				for _, line := range []string{
					fmt.Sprintf("%s %c0, %c1", op, narrow, wide),
					fmt.Sprintf("%s v0.%d%c, v1.%d%c", op, lanes, narrow, lanes, wide),
					fmt.Sprintf("%s2 v0.%d%c, v1.%d%c", op, 2*lanes, narrow, lanes, wide),
				} {
					samples = append(samples, arm64NarrowSample{assembly: line + immediate, bits: bits, shift: shift})
				}
			}
		}
	}
	return samples
}

func assembleARM64NarrowSamples(t *testing.T, samples []arm64NarrowSample) []uint32 {
	t.Helper()
	lines := make([]string, len(samples))
	for i, sample := range samples {
		lines[i] = sample.assembly
	}
	return assembleARM64LLVMWords(t, lines, "")
}

func TestARM64SaturatingNarrowLLVMMatrix(t *testing.T) {
	samples := arm64NarrowSamples(true)
	words := assembleARM64NarrowSamples(t, samples)
	if len(words) != 1035 {
		t.Fatalf("got %d formats, want 27 unshifted and 1008 shifted", len(words))
	}
	var source strings.Builder
	source.WriteString("TEXT narrowMatrix(SB),4,$0-0\n")
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
				Sigs: map[string]FuncSig{"narrowMatrix": {Name: "narrowMatrix", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Count(ir, `<16 x i8> asm sideeffect`); got != len(words) {
				t.Fatalf("got %d native narrowing instructions, want %d", got, len(words))
			}
			compileLLVMToObject(t, llc, triple, "narrow-matrix.ll", "narrow-matrix.o", ir)
		})
	}
}

func TestARM64RawIntegerNarrowRejectsReservedEncodings(t *testing.T) {
	for word, reason := range map[uint32]string{
		0x1e214820: "scalar SQXTN without Q",
		0x5e212820: "scalar XTN",
		0x0ee14820: "SQXTN size=3",
		0x0f079420: "SQSHRN outside the immediate class",
		0x0f409420: "SQSHRN destination would be 64-bit",
		0x0e207820: "adjacent SQABS",
	} {
		if form, ok := decodeARM64RawIntegerNarrow(word); ok {
			t.Errorf("%s (%#08x) decoded as %+v", reason, word, form)
		}
	}
}

func TestCrossLinuxRuntimeMatrixARM64SaturatingNarrowQC(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	samples := append(arm64NarrowSamples(false),
		arm64NarrowSample{assembly: "sqxtn2 v1.16b, v1.8h", bits: 8, destination: 1},
		arm64NarrowSample{assembly: "uqrshrn2 v1.8h, v1.4s, #7", bits: 16, shift: 7, destination: 1},
		arm64NarrowSample{assembly: "sqxtun v0.8b, v1.8h", bits: 8, dead: true, named: "VSQXTUN V1.H8, V0.B8"},
		arm64NarrowSample{assembly: "sqrshrn2 v0.16b, v1.8h, #3", bits: 8, shift: 3, dead: true},
	)
	words := assembleARM64NarrowSamples(t, samples)
	var source, driver, checks strings.Builder
	driver.WriteString(`
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef void (*narrow_fn)(const void *, void *);
static int check(narrow_fn translate, narrow_fn original, const char *instruction,
                 unsigned bits, unsigned shift, int dead) {
  uint64_t sign = UINT64_C(1) << (bits - 1);
  uint64_t wide_sign = UINT64_C(1) << (2 * bits - 1);
  uint64_t round = shift ? UINT64_C(1) << (shift - 1) : 0;
  uint64_t signed_edge = sign << shift;
  uint64_t unsigned_edge = (2 * sign - 1) << shift;
  uint64_t values[] = {0, 1, UINT64_MAX, wide_sign, wide_sign - 1,
                       signed_edge - 1, signed_edge, signed_edge - round,
                       -signed_edge, -signed_edge - 1, unsigned_edge,
                       unsigned_edge + round, -round};
  unsigned n = sizeof(values) / sizeof(values[0]);
  for (unsigned seed = 0; seed < 2; ++seed) {
    for (unsigned row = 0; row < n; ++row) {
      uint64_t input[5] = {0x123456789abcdef0ULL, 0x0fedcba987654321ULL};
      uint64_t got[3] = {0}, want[3] = {0};
      unsigned char *source = (unsigned char *)(input + 2);
      unsigned bytes = bits / 4;
      for (unsigned i = 0; i < 16; i += bytes)
        memcpy(source + i, &values[(row + i/bytes) % n], bytes);
      input[4] = seed ? UINT64_C(0x8000000) : 0;
      original(input, want);
      translate(input, got);
      if (got[2] != want[2] || (!dead && memcmp(got, want, 16))) {
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
		name := fmt.Sprintf("nativeNarrow%d", i)
		fmt.Fprintf(&source, `TEXT %s(SB),4,$0-16
MOVD input+0(FP), R0
MOVD out+8(FP), R1
MRS FPSR, R10
MOVD 32(R0), R11
MSR R11, FPSR
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
		source.WriteString("MRS FPSR, R11\nMSR R10, FPSR\nMOVD R11, 16(R1)\nRET\n")
		sigs[name] = sigWithClassicFrame(name, []LLVMType{Ptr, Ptr}, Void)
		fmt.Fprintf(&driver, `extern void %[1]s(const void *, void *);
static void original%[2]d(const void *input, void *output) {
  uint64_t old, status, seed = ((const uint64_t *)input)[4];
  __asm__ volatile("mrs %%0, fpsr\nmsr fpsr, %%4\n"
                   "ld1 {v0.16b, v1.16b}, [%%2]\n"
                   ".inst %#[3]x\nst1 {v%[4]d.16b}, [%%3]\n"
                   "mrs %%1, fpsr\nmsr fpsr, %%0"
                  : "=&r"(old), "=&r"(status) : "r"(input), "r"(output), "r"(seed)
                  : "v0", "v1", "memory");
  ((uint64_t *)output)[2] = status;
}
`, name, i, words[i], sample.destination)
		fmt.Fprintf(&checks, "  if (check(%s, original%d, %q, %d, %d, %d)) return 1;\n",
			name, i, sample.assembly, sample.bits, sample.shift, dead)
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
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "arm64_sat_narrow",
				triple, input, driver.String(), runner, opt)
		})
	}
}
