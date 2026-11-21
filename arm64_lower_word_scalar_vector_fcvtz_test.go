package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type arm64ScalarSIMDFloatToIntCase struct {
	name, register string
	bits           int
	unsigned       bool
}

func arm64SIMDFloatToIntCases(t *testing.T, vector bool) ([]arm64ScalarSIMDFloatToIntCase, []uint32) {
	t.Helper()
	var forms []arm64ScalarSIMDFloatToIntCase
	var instructions []string
	type layout struct {
		register string
		bits     int
	}
	layouts := []layout{{"h", 16}, {"s", 32}, {"d", 64}}
	if vector {
		layouts = []layout{{"4h", 16}, {"8h", 16}, {"2s", 32}, {"4s", 32}, {"2d", 64}}
	}
	for _, mode := range []string{"n", "a", "p", "m", "z"} {
		for _, sign := range []string{"s", "u"} {
			for _, width := range layouts {
				name := "fcvt" + mode + sign
				forms = append(forms, arm64ScalarSIMDFloatToIntCase{name, width.register, width.bits, sign == "u"})
				register := width.register + "0"
				if vector {
					register = "v0." + width.register
				}
				instructions = append(instructions, fmt.Sprintf("%s %s, %s", name, register, register))
			}
		}
	}
	return forms, assembleARM64LLVMWords(t, instructions, "+fullfp16")
}

func TestARM64RawScalarVectorFCVTZCompleteFamily(t *testing.T) {
	forms, encodings := arm64SIMDFloatToIntCases(t, false)
	for index, form := range forms {
		for sourceReg := 0; sourceReg < 32; sourceReg++ {
			for destinationReg := 0; destinationReg < 32; destinationReg++ {
				word := encodings[index] | uint32(sourceReg)<<5 | uint32(destinationReg)
				decoded, ok := decodeARM64RawSIMDFloatToInt(word)
				if !ok || decoded.arrangement != (arm64VectorArrangement{elementBits: form.bits, lanes: 1}) || decoded.unsigned != form.unsigned ||
					decoded.source != sourceReg || decoded.destination != destinationReg {
					t.Fatalf("%s %s fields not decoded for %#08x: %+v, ok=%v", form.name, form.register, word, decoded, ok)
				}
			}
		}
	}

	var source strings.Builder
	source.WriteString("TEXT rawscalarvectorfcvtz(SB),$0-0\n")
	for index, form := range forms {
		word := encodings[index] | 31<<5 | 30
		fmt.Fprintf(&source, "\tWORD $%#08x // %s %s30, %s31\n", word, form.name, form.register, form.register)
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
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-unknown-freebsd",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"rawscalarvectorfcvtz": {Name: "rawscalarvectorfcvtz", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, form := range forms {
				fragment := fmt.Sprintf("%s ${0:%s}, ${1:%s}", form.name, form.register, form.register)
				if !strings.Contains(ir, fragment) {
					t.Fatalf("%s IR omitted %q", form.name, fragment)
				}
			}
			if !strings.Contains(ir, `"target-features"="+fullfp16"`) {
				t.Fatal("scalar half conversion IR omitted +fullfp16")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-scalar-vector-fcvtz.ll", "arm64-raw-scalar-vector-fcvtz.o", ir)
		})
	}
}

func TestCrossLinuxRuntimeMatrixARM64RawScalarSIMDFloatToInt(t *testing.T) {
	runARM64SIMDFloatToInt(t, false)
}

func TestCrossLinuxRuntimeMatrixARM64RawVectorSIMDFloatToInt(t *testing.T) {
	runARM64SIMDFloatToInt(t, true)
}

type arm64NativeConversionCase struct {
	word                        uint32
	instruction                 string
	inputBits                   int
	inputGP, outputGP, inputInt bool
}

func runARM64SIMDFloatToInt(t *testing.T, vector bool) {
	t.Helper()
	forms, encodings := arm64SIMDFloatToIntCases(t, vector)
	cases := make([]arm64NativeConversionCase, 0, len(forms))
	for index, form := range forms {
		destination, input := form.register+"23", form.register+"6"
		if vector {
			destination, input = "v23."+form.register, "v6."+form.register
		}
		cases = append(cases, arm64NativeConversionCase{
			word: encodings[index] | 6<<5 | 23, inputBits: form.bits,
			instruction: fmt.Sprintf("%s %s,%s", form.name, destination, input),
		})
	}
	runARM64NativeConversionCases(t, cases)
}

func arm64NativeConversionPrograms(forms []arm64NativeConversionCase) (string, map[string]FuncSig, string) {
	var source, mainC, cases strings.Builder
	sigs := make(map[string]FuncSig, len(forms))
	mainC.WriteString("#include <stdint.h>\n#include <stdio.h>\n")
	for index, form := range forms {
		name := fmt.Sprintf("nativeConvert%d", index)
		load, preload, store := "VLD1 (R0), [V6.B16]", "VLD1 (R1), [V23.B16]", "VST1 [V23.B16], (R1)"
		input, output, nativePreload := "q6", "q23", "ldr q23,[%1]\\n\\t"
		if form.inputGP {
			load, input = "MOVD (R0), R6", "x6"
		}
		if form.outputGP {
			preload, store, output, nativePreload = "", "MOVD R23, (R1)", "x23", ""
		}
		fmt.Fprintf(&source, `
TEXT %s(SB),4,$0-16
	MOVD input+0(FP), R0
	MOVD output+8(FP), R1
	%s
	%s
	WORD $%#08x
	%s
	RET
`, name, load, preload, form.word, store)
		sigs[name] = arm64SM3Signature(name)
		fmt.Fprintf(&mainC, `
extern void %s(const uint64_t *, uint64_t *);
static void native%d(const uint64_t *in, uint64_t *out) {
  __asm__ volatile("ldr %s,[%%0]\n\t%s%s\n\tstr %s,[%%1]"
                   : : "r"(in), "r"(out) : "x6", "x23", "v6", "v23", "memory");
}
`, name, index, input, nativePreload, form.instruction, output)
		integer := 0
		if form.inputInt {
			integer = 1
		}
		fmt.Fprintf(&cases, "  {%s, native%d, %d, %d},\n", name, index, form.inputBits, integer)
	}

	mainC.WriteString(`
typedef void (*convert)(const uint64_t *, uint64_t *);
static const struct { convert translated, native; int bits, integer; } cases[] = {
`)
	mainC.WriteString(cases.String())
	mainC.WriteString(`
};
static void set_status(uint64_t value) {
  __asm__ volatile("msr fpsr,%0" : : "r"(value) : "memory");
}
static uint64_t status(void) {
  uint64_t value;
  __asm__ volatile("mrs %0,fpsr" : "=r"(value) : : "memory");
  return value;
}
static void set_control(uint64_t value) {
  __asm__ volatile("msr fpcr,%0" : : "r"(value) : "memory");
}
static uint64_t control(void) {
  uint64_t value;
  __asm__ volatile("mrs %0,fpcr" : "=r"(value) : : "memory");
  return value;
}
int main(void) {
  // Even and odd ties, a subnormal, positive infinity and signaling NaN.
  static const uint64_t values[][3] = {
    {0x4100, 0x40200000, 0x4004000000000000},
    {0x4300, 0x40600000, 0x400c000000000000},
    {0x0001, 0x00000001, 0x0000000000000001},
    {0x7c00, 0x7f800000, 0x7ff0000000000000},
    {0x7c01, 0x7f800001, 0x7ff0000000000001},
  };
  static const uint64_t integers[][3] = {
    {1, 1, 1},
    {0x4001, 0x01000001, 0x0020000000000001},
    {0x7fff, 0x7fffffff, 0x7fffffffffffffff},
    {0x8000, 0x80000000, 0x8000000000000000},
    {0xffff, 0xffffffff, 0xffffffffffffffff},
  };
  uint64_t previous = status();
  uint64_t previous_control = control();
  for (unsigned i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i) {
    int width = cases[i].bits;
    int column = width == 16 ? 0 : width == 32 ? 1 : 2;
    for (unsigned j = 0; j < sizeof(values)/sizeof(values[0]); ++j) {
      for (uint64_t sign = 0; sign < 2; ++sign) {
        uint64_t input[2] = {0, 0};
        for (int lane = 0; lane < 128/width; ++lane) {
          unsigned next = (j + lane) % (sizeof(values)/sizeof(values[0]));
          uint64_t base = cases[i].integer ? integers[next][column] : values[next][column];
          uint64_t bits = base ^ ((sign ^ (lane & 1)) << (width-1));
          input[lane*width/64] |= bits << ((lane*width) % 64);
        }
        for (uint64_t rounding = 0; rounding < 4; ++rounding) {
          uint64_t actual[] = {0x9876543210fedcba, 0xfedcba9876543210};
          uint64_t expected[] = {actual[0], actual[1]};
          uint64_t mode = rounding << 22;
          set_control(mode);
          set_status(0x08000000);
          cases[i].native(input, expected);
          uint64_t want_control = control();
          uint64_t want_status = status();
          set_control(mode);
          set_status(0x08000000);
          cases[i].translated(input, actual);
          if (actual[0] != expected[0] || actual[1] != expected[1] ||
              status() != want_status || control() != want_control) {
            fprintf(stderr, "conversion %u input %u sign %llu mode %llu: result or FP status differs\n",
                    i, j, (unsigned long long)sign, (unsigned long long)rounding);
            return 1;
          }
        }
      }
    }
  }
  set_status(previous);
  set_control(previous_control);
  return 0;
}
`)
	return source.String(), sigs, mainC.String()
}

func runARM64NativeConversionCases(t *testing.T, forms []arm64NativeConversionCase) {
	t.Helper()
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	source, sigs, mainC := arm64NativeConversionPrograms(forms)
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	compiler = append(compiler, "-march=armv8.2-a+fp16")
	// Cross runs need a CPU exposing FEAT_FP16. The host run uses its native CPU.
	if len(runner) != 0 {
		runner = append(runner, "-cpu", "max")
	}
	for _, variant := range []struct {
		name, ir string
	}{{"original", ir}, {"optimized", armFloatEffectOptimizedIR(t, ir)}} {
		for _, level := range []int{0, 2} {
			t.Run(fmt.Sprintf("%s/O%d", variant.name, level), func(t *testing.T) {
				compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "arm64_native_conversion", triple, variant.ir, mainC, runner, level)
			})
		}
	}
}

func TestARM64RawScalarVectorFCVTZRejectsAdjacentEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x1e380000, // FCVTZS to a general-purpose register.
		0x5ea1d800, // Scalar FRECPE, not a conversion.
		0x5ee9b800, // Reserved size/opcode combination.
		0x1e21a800, // Scalar Advanced SIMD selector with Q=0.
	} {
		if _, ok := decodeARM64RawSIMDFloatToInt(word); ok {
			t.Fatalf("scalar vector FCVTZ decoder accepted adjacent encoding %#08x", word)
		}
	}
}
