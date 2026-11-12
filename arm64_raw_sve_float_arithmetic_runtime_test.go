package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func testARM64RawSVEFloatArithmeticRuntime(t *testing.T, llc string) {
	testARM64RawSVEFloatBinaryRuntime(t, llc, arm64RawSVEFloatArithmeticCases())
}

func testARM64RawSVEFloatDivideScaleRuntime(t *testing.T, llc string) {
	testARM64RawSVEFloatBinaryRuntime(t, llc, arm64RawSVEFloatDivideScaleCases())
}

func testARM64RawSVEFloatBinaryRuntime(t *testing.T, llc string, forms []arm64RawSVEFloatArithmeticCase) {
	type runtimeCase struct {
		form                arm64RawSVEFloatArithmeticCase
		destination, second int
		native              []string
	}
	var cases []runtimeCase
	var allNative []string
	for _, form := range forms {
		second := 29
		if form.mode == "indexed" {
			second = 7
			if form.size == 3 {
				second = 15
			}
		}
		for _, destination := range []int{31, 30, second} {
			native := []string{
				"ptrue p0.b", "ld1b { z30.b }, p0/z, [x0]", "ld1b { z31.b }, p0/z, [x0]",
				fmt.Sprintf("ld1b { z%d.b }, p0/z, [x1]", second),
				"ld1b { z28.b }, p0/z, [x2]", "cmpne p7.b, p0/z, z28.b, #0",
				form.assembly(destination, 30, second, 7),
				fmt.Sprintf("st1b { z%d.b }, p0, [x3]", destination),
			}
			cases = append(cases, runtimeCase{form, destination, second, native})
			allNative = append(allNative, native...)
		}
	}
	words := assembleARM64LLVMWords(t, allNative, "+sve")
	var source, declarations, checks strings.Builder
	declarations.WriteString(arm64SVEFloatArithmeticRuntimeReference)
	sigs := make(map[string]FuncSig)
	for _, test := range cases {
		name := fmt.Sprintf("float_arithmetic_%d", len(sigs))
		fmt.Fprintf(&source, "TEXT %s(SB),$0-32\nMOVD a+0(FP),R0\nMOVD b+8(FP),R1\nMOVD mask+16(FP),R2\nMOVD out+24(FP),R3\n", name)
		for _, word := range words[:len(test.native)] {
			fmt.Fprintf(&source, "WORD $%#08x\n", word)
		}
		words = words[len(test.native):]
		source.WriteString("RET\n")
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1},
			{Offset: 16, Type: Ptr, Index: 2, Field: -1}, {Offset: 24, Type: Ptr, Index: 3, Field: -1},
		}}}
		assembly := strings.NewReplacer("[x0]", "[%[a]]", "[x1]", "[%[b]]", "[x2]", "[%[mask]]", "[x3]", "[%[out]]").Replace(strings.Join(test.native, "\\n\\t"))
		fmt.Fprintf(&declarations, `extern void %[1]s(const void *, const void *, const void *, void *);
static void %[1]s_native(const void *a, const void *b, const void *mask, void *out) {
  __asm__ volatile("%[2]s" :: [a]"r"(a), [b]"r"(b), [mask]"r"(mask), [out]"r"(out)
    : "p0", "p7", "z7", "z15", "z28", "z29", "z30", "z31", "memory");
}
`, name, assembly)
		predicated, firstB, lane := 0, 0, -1
		if test.form.mode == "predicated" || test.form.mode == "immediate" {
			predicated = 1
			if test.destination == test.second {
				firstB = 1
			}
		} else if test.form.mode == "indexed" {
			lane = test.form.lane
		}
		operation := map[string]int{"fadd": 0, "fsub": 1, "fsubr": 2, "fmul": 3, "fdiv": 4, "fdivr": 5, "fscale": 6}[test.form.op]
		fmt.Fprintf(&checks, "  if (check_float_arithmetic(vl, %d, %d, %d, %d, %d, %.1f, %s, %s_native, %q)) return 1;\n",
			1<<test.form.size, operation, predicated, firstB, lane, test.form.immediate, name, name, name)
	}
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	const triple = "aarch64-unknown-linux-gnu"
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	main := arm64SVEVectorLengthMain(declarations.String(), checks.String())
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc", "-march=armv8.2-a+sve"}, "raw_float_arithmetic", triple, ir, main,
		[]string{"qemu-aarch64", "-cpu", "max,sve-max-vq=16", "-L", "/usr/aarch64-linux-gnu"})
}

const arm64SVEFloatArithmeticRuntimeReference = `
#include <math.h>
typedef void (*float_arithmetic_fn)(const void *, const void *, const void *, void *);
static double unpack_float(const unsigned char *p, unsigned bytes) {
  if (bytes == 2) { _Float16 x; memcpy(&x, p, 2); return x; }
  if (bytes == 4) { float x; memcpy(&x, p, 4); return x; }
  double x; memcpy(&x, p, 8); return x;
}
static void pack_float(unsigned char *p, unsigned bytes, double x) {
  if (bytes == 2) { _Float16 y = x; memcpy(p, &y, 2); }
  else if (bytes == 4) { float y = x; memcpy(p, &y, 4); }
  else memcpy(p, &x, 8);
}
__attribute__((noinline, noclone))
static int check_float_arithmetic(unsigned vl, unsigned bytes, unsigned operation,
    int predicated, int first_b, int lane, double immediate, float_arithmetic_fn translated,
    float_arithmetic_fn native_instruction, const char *name) {
  const uint64_t patterns[3][12] = {
    {0, 0x8000, 0x3c00, 0xbc00, 0x7bff, 1, 0x0400, 0x7c00, 0xfc00, 0x7e13, 0x7c23, 0x3555},
    {0, 0x80000000, 0x3f800000, 0xbf800000, 0x7f7fffff, 1, 0x00800000, 0x7f800000, 0xff800000, 0x7fc00013, 0x7f800023, 0x3eaaaaab},
    {0, 0x8000000000000000ULL, 0x3ff0000000000000ULL, 0xbff0000000000000ULL,
     0x7fefffffffffffffULL, 1, 0x0010000000000000ULL, 0x7ff0000000000000ULL,
     0xfff0000000000000ULL, 0x7ff8000000000013ULL, 0x7ff0000000000023ULL, 0x3fd5555555555555ULL}
  };
  unsigned char a[256], b[256], mask[256], got[256], native[256], scalar[256];
  unsigned row = bytes == 2 ? 0 : bytes == 4 ? 1 : 2;
  for (unsigned phase = 0; phase < 16; phase++) {
    for (unsigned i = 0; i < sizeof(a); i += bytes) {
      unsigned element = i / bytes;
      uint64_t x = patterns[row][(element + phase) % 12], y = patterns[row][(element * 3 + phase * 7) % 12];
      if (operation == 6) {
        const int64_t exponents[] = {0, 1, -1, 2, -2, 127, -149, 1023, -1074, 32767, -32768, INT64_MIN};
        y = (uint64_t)exponents[(element * 3 + phase * 7) % 12];
      }
      memcpy(a + i, &x, bytes);
      memcpy(b + i, &y, bytes);
      for (unsigned j = 0; j < bytes; j++) mask[i + j] = phase < 2 ? phase : (element + phase) % 3 != 0;
    }
    memset(got, 0x5a, sizeof(got));
    memset(native, 0x5a, sizeof(native));
    memset(scalar, 0x5a, sizeof(scalar));
    for (unsigned i = 0; i < vl; i += bytes) {
      const unsigned char *first = (first_b ? b : a) + i;
      if (predicated && !mask[i]) { memcpy(scalar + i, first, bytes); continue; }
      double x = unpack_float(first, bytes);
      double y = immediate ? immediate : unpack_float(b + (lane < 0 ? i : (i & ~15u) + lane * bytes), bytes);
      double value;
      switch (operation) {
        case 0: value = x + y; break;
        case 1: value = x - y; break;
        case 2: value = y - x; break;
        case 3: value = x * y; break;
        case 4: value = x / y; break;
        case 5: value = y / x; break;
        default: {
          uint64_t encoded = 0;
          memcpy(&encoded, b + i, bytes);
          int64_t exponent = bytes == 2 ? (int16_t)encoded : bytes == 4 ? (int32_t)encoded : (int64_t)encoded;
          int clamped = exponent > 65536 ? 65536 : exponent < -65536 ? -65536 : (int)exponent;
          value = scalbn(x, clamped);
          break;
        }
      }
      pack_float(scalar + i, bytes, value);
    }
    native_instruction(a, b, mask, native);
    translated(a, b, mask, got);
    if (memcmp(got, native, sizeof(got))) {
      fprintf(stderr, "%s: native mismatch vl=%u phase=%u\n", name, vl, phase);
      return 1;
    }
    for (unsigned i = 0; i < vl; i += bytes) {
      // The native comparison above checks exact NaN payloads and inactive
      // signaling NaNs; scalar C conversions may quiet or canonicalize NaNs.
      if (isnan(unpack_float(scalar + i, bytes)) && isnan(unpack_float(got + i, bytes))) continue;
      if (memcmp(got + i, scalar + i, bytes)) {
        fprintf(stderr, "%s: scalar mismatch vl=%u phase=%u offset=%u\n", name, vl, phase, i);
        return 1;
      }
    }
  }
  return 0;
}
`
