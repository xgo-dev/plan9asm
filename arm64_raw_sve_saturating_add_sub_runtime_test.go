package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func testARM64RawSVESaturatingAddSubRuntime(t *testing.T, llc string) {
	type runtimeCase struct {
		form        arm64SVESaturatingAddSubCase
		destination int
		native      []string
		named       bool
	}
	var cases []runtimeCase
	var allNative []string
	for _, form := range arm64SVESaturatingAddSubCases() {
		for _, destination := range []int{31, 30, 29} {
			native := []string{
				"ptrue p0.b", "ld1b { z30.b }, p0/z, [x0]", "ld1b { z31.b }, p0/z, [x0]",
				"ld1b { z29.b }, p0/z, [x1]", "ld1b { z28.b }, p0/z, [x2]", "cmpne p7.b, p0/z, z28.b, #0",
				form.assembly(destination, 30, 29, 7),
				fmt.Sprintf("st1b { z%d.b }, p0, [x3]", destination),
			}
			cases = append(cases, runtimeCase{form: form, destination: destination, native: native})
			allNative = append(allNative, native...)
			if form.mode == arm64SVEAddImmediate && strings.HasPrefix(form.op, "s") && uint64(form.immediate) >= uint64(1)<<((8<<form.size)-1) {
				cases = append(cases, runtimeCase{form: form, destination: destination, native: native, named: true})
				allNative = append(allNative, native...)
			}
		}
	}
	words := assembleARM64LLVMWords(t, allNative, "+sve2")
	var source, declarations, checks strings.Builder
	declarations.WriteString(arm64SVESaturatingAddSubRuntimeReference)
	sigs := make(map[string]FuncSig)
	for _, test := range cases {
		name := fmt.Sprintf("saturating_%s_%d", test.form.op, len(sigs))
		fmt.Fprintf(&source, "TEXT %s(SB),$0-32\nMOVD a+0(FP),R0\nMOVD b+8(FP),R1\nMOVD mask+16(FP),R2\nMOVD out+24(FP),R3\n", name)
		for index, word := range words[:len(test.native)] {
			if test.named && index == 6 {
				register := fmt.Sprintf("Z%d.%c", test.destination, "BHSD"[test.form.size])
				fmt.Fprintf(&source, "Z%s $%d, %s, %s\n", strings.ToUpper(test.form.op), test.form.immediate, register, register)
				continue
			}
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
    : "p0", "p7", "z28", "z29", "z30", "z31", "memory");
}
`, name, assembly)
		signed, subtract, reverse, predicated, firstB := 0, 0, 0, 0, 0
		if strings.HasPrefix(test.form.op, "s") {
			signed = 1
		}
		if strings.Contains(test.form.op, "sub") {
			subtract = 1
		}
		if strings.HasSuffix(test.form.op, "r") {
			reverse = 1
		}
		if test.form.mode == arm64SVEAddPredicated {
			predicated = 1
		}
		if test.form.mode != arm64SVEAddUnpredicated && test.destination == 29 {
			firstB = 1
		}
		immediate := -1
		if test.form.mode == arm64SVEAddImmediate {
			immediate = test.form.immediate
		}
		fmt.Fprintf(&checks, "  if (check_saturating(vl, %d, %d, %d, %d, %d, %d, %d, %s, %s_native, %q)) return 1;\n",
			8<<test.form.size, signed, subtract, reverse, predicated, firstB, immediate, name, name, name)
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
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc", "-march=armv8.2-a+sve2"}, "raw_saturating", triple, ir, main,
		[]string{"qemu-aarch64", "-cpu", "max,sve-max-vq=16", "-L", "/usr/aarch64-linux-gnu"})
}

const arm64SVESaturatingAddSubRuntimeReference = `
typedef void (*saturating_fn)(const void *, const void *, const void *, void *);
__attribute__((noinline, noclone))
static int check_saturating(unsigned vl, unsigned bits, int signed_value, int subtract, int reverse,
    int predicated, int first_b, int immediate, saturating_fn translated,
    saturating_fn native_instruction, const char *name) {
  unsigned char a[256], b[256], mask[256], got[256], native[256], scalar[256];
  unsigned bytes = bits / 8;
  uint64_t sign = UINT64_C(1) << (bits - 1), maximum = UINT64_MAX >> (64 - bits);
  uint64_t values[] = {0, 1, maximum, sign, sign - 1, sign + 1, 2, 3};
  for (unsigned phase = 0; phase < 16; phase++) {
    for (unsigned i = 0; i < sizeof(a); i += bytes) {
      unsigned lane = i / bytes;
      uint64_t x = values[(lane + phase) % 8], y = values[(lane * 3 + phase * 7) % 8];
      if (phase >= 8) {
        x = 0x76543210abcdef01ULL * (lane + phase);
        y = 0xfedcba9876543211ULL * (lane * 7 + phase);
      }
      memcpy(a + i, &x, bytes);
      memcpy(b + i, &y, bytes);
      for (unsigned j = 0; j < bytes; j++) mask[i + j] = phase < 2 ? phase : (lane + phase) % 3 != 0;
    }
    memset(got, 0x5a, sizeof(got));
    memset(native, 0x5a, sizeof(native));
    memset(scalar, 0x5a, sizeof(scalar));
    for (unsigned i = 0; i < vl; i += bytes) {
      uint64_t x = 0, y = 0;
      memcpy(&x, (first_b ? b : a) + i, bytes);
      memcpy(&y, b + i, bytes);
      uint64_t value = x;
      if (!predicated || mask[i]) {
        __int128 sx = x, sy = y;
        __int128 minimum = 0, limit = maximum;
        if (signed_value) {
          if (x & sign) sx -= (__int128)1 << bits;
          if (y & sign) sy -= (__int128)1 << bits;
          minimum = -(__int128)sign;
          limit = sign - 1;
        }
        // Saturating immediates are unsigned, even for signed operations.
        if (immediate >= 0) sy = immediate;
        __int128 result = subtract ? (reverse ? sy - sx : sx - sy) : sx + sy;
        if (result < minimum) result = minimum;
        if (result > limit) result = limit;
        value = (uint64_t)result;
      }
      memcpy(scalar + i, &value, bytes);
    }
    native_instruction(a, b, mask, native);
    translated(a, b, mask, got);
    if (memcmp(got, native, sizeof(got)) || memcmp(got, scalar, sizeof(got))) {
      fprintf(stderr, "%s: bits=%u vl=%u phase=%u imm=%d translated/native=%d native/scalar=%d\n",
          name, bits, vl, phase, immediate, memcmp(got, native, sizeof(got)), memcmp(native, scalar, sizeof(got)));
      return 1;
    }
  }
  return 0;
}
`
