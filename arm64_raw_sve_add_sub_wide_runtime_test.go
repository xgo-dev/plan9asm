package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func testARM64RawSVEAddSubWideRuntime(t *testing.T, llc string) {
	type runtimeCase struct {
		op, name string
		size     int
		native   []string
	}
	var cases []runtimeCase
	var allNative []string
	for _, op := range arm64SVEAddSubWideNativeOps {
		for size := 1; size < 4; size++ {
			for _, destination := range []int{31, 30, 29} {
				native := []string{
					"ptrue p0.b", "ld1b { z30.b }, p0/z, [x0]", "ld1b { z29.b }, p0/z, [x1]",
					arm64SVEAddSubWideAssembly(op, size, destination, 30, 29),
					fmt.Sprintf("st1b { z%d.b }, p0, [x2]", destination),
				}
				cases = append(cases, runtimeCase{op, fmt.Sprintf("add_sub_wide_%d", len(cases)), size, native})
				allNative = append(allNative, native...)
			}
		}
	}
	words := assembleARM64LLVMWords(t, allNative, "+sve2")
	var source, declarations, checks strings.Builder
	declarations.WriteString(arm64SVEAddSubWideRuntimeReference)
	sigs := make(map[string]FuncSig)
	for _, test := range cases {
		fmt.Fprintf(&source, "TEXT %s(SB),$0-24\nMOVD a+0(FP),R0\nMOVD b+8(FP),R1\nMOVD out+16(FP),R2\n", test.name)
		for _, word := range words[:len(test.native)] {
			fmt.Fprintf(&source, "WORD $%#08x\n", word)
		}
		words = words[len(test.native):]
		source.WriteString("RET\n")
		sigs[test.name] = FuncSig{Name: test.name, Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1},
			{Offset: 16, Type: Ptr, Index: 2, Field: -1},
		}}}
		assembly := strings.NewReplacer("[x0]", "[%[a]]", "[x1]", "[%[b]]", "[x2]", "[%[out]]").Replace(strings.Join(test.native, "\\n\\t"))
		fmt.Fprintf(&declarations, `extern void %[1]s(const void *, const void *, void *);
static void %[1]s_native(const void *a, const void *b, void *out) {
  __asm__ volatile("%[2]s" :: [a]"r"(a), [b]"r"(b), [out]"r"(out)
    : "p0", "z29", "z30", "z31", "memory");
}
`, test.name, assembly)
		signed, subtract, top := 0, 0, 0
		if test.op[0] == 's' {
			signed = 1
		}
		if strings.Contains(test.op, "sub") {
			subtract = 1
		}
		if strings.HasSuffix(test.op, "t") {
			top = 1
		}
		fmt.Fprintf(&checks, "  if (check_add_sub_wide(vl, %d, %d, %d, %d, %s, %s_native, %q)) return 1;\n",
			1<<test.size, signed, subtract, top, test.name, test.name, test.name)
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
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc", "-march=armv8.2-a+sve2"}, "raw_add_sub_wide", triple, ir, main,
		[]string{"qemu-aarch64", "-cpu", "max,sve-max-vq=16", "-L", "/usr/aarch64-linux-gnu"})
}

const arm64SVEAddSubWideRuntimeReference = `
typedef void (*add_sub_wide_fn)(const void *, const void *, void *);
__attribute__((noinline, noclone))
static int check_add_sub_wide(unsigned vl, unsigned bytes, int signed_input, int subtract,
    int top, add_sub_wide_fn translated, add_sub_wide_fn native_instruction, const char *name) {
  unsigned char a[256], b[256], got[256], native[256], scalar[256];
  const unsigned narrow = bytes / 2, narrow_bits = narrow * 8;
  uint64_t maximum = UINT64_MAX >> (64 - narrow_bits), sign = UINT64_C(1) << (narrow_bits - 1);
  uint64_t values[] = {0, 1, maximum, sign, sign - 1, sign + 1, 2, 3};
  for (unsigned phase = 0; phase < 16; phase++) {
    for (unsigned i = 0; i < sizeof(a); i++) a[i] = phase == 0 ? 0xff : i * 71 + phase * 53;
    for (unsigned i = 0; i < sizeof(b); i += narrow) {
      uint64_t value = phase < 8 ? values[(i / narrow + phase) % 8] : 0x456789abcdef0123ULL * (i + phase);
      memcpy(b + i, &value, narrow);
    }
    memset(got, 0x5a, sizeof(got));
    memset(native, 0x5a, sizeof(native));
    memset(scalar, 0x5a, sizeof(scalar));
    for (unsigned i = 0; i < vl; i += bytes) {
      uint64_t x = 0, y = 0;
      memcpy(&x, a + i, bytes);
      memcpy(&y, b + i + top * narrow, narrow);
      if (signed_input && (y & sign)) y |= ~maximum;
      uint64_t value = subtract ? x - y : x + y;
      memcpy(scalar + i, &value, bytes);
    }
    native_instruction(a, b, native);
    translated(a, b, got);
    if (memcmp(got, native, sizeof(got)) || memcmp(got, scalar, sizeof(got))) {
      fprintf(stderr, "%s: vl=%u phase=%u\n", name, vl, phase);
      return 1;
    }
  }
  return 0;
}
`
