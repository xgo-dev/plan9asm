package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func testARM64RawSVEAddressGenerationRuntime(t *testing.T, llc string) {
	type runtimeCase struct {
		name        string
		mode, shift int
		native      []string
	}
	var cases []runtimeCase
	var allNative []string
	for mode := 0; mode < 4; mode++ {
		for shift := 0; shift < 4; shift++ {
			for _, destination := range []int{31, 30, 29} {
				native := []string{
					"ptrue p0.b", "ld1b { z30.b }, p0/z, [x0]", "ld1b { z29.b }, p0/z, [x1]",
					arm64SVEAddressGenerationAssembly(mode, shift, destination, 30, 29),
					fmt.Sprintf("st1b { z%d.b }, p0, [x2]", destination),
				}
				cases = append(cases, runtimeCase{fmt.Sprintf("address_generation_%d", len(cases)), mode, shift, native})
				allNative = append(allNative, native...)
			}
		}
	}
	words := assembleARM64LLVMWords(t, allNative, "+sve")
	var source, declarations, checks strings.Builder
	declarations.WriteString(arm64SVEAddressGenerationRuntimeReference)
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
		fmt.Fprintf(&checks, "  if (check_address_generation(vl, %d, %d, %s, %s_native, %q)) return 1;\n",
			test.mode, test.shift, test.name, test.name, test.name)
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
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc", "-march=armv8.2-a+sve"}, "raw_address_generation", triple, ir, main,
		[]string{"qemu-aarch64", "-cpu", "max,sve-max-vq=16", "-L", "/usr/aarch64-linux-gnu"})
}

const arm64SVEAddressGenerationRuntimeReference = `
typedef void (*address_generation_fn)(const void *, const void *, void *);
__attribute__((noinline, noclone))
static int check_address_generation(unsigned vl, unsigned mode, unsigned shift,
    address_generation_fn translated, address_generation_fn native_instruction, const char *name) {
  unsigned char base[256], index[256], got[256], native[256], scalar[256];
  const unsigned bytes = mode == 2 ? 4 : 8;
  const uint64_t values[] = {0, 1, UINT64_MAX, UINT64_C(0x80000000), UINT64_C(0x7fffffff),
    UINT64_C(0x8000000000000000), UINT64_C(0xffffffff00000001), UINT64_C(0x12345678ffffffff)};
  for (unsigned phase = 0; phase < 16; phase++) {
    for (unsigned i = 0; i < sizeof(base); i += bytes) {
      uint64_t a = values[(i / bytes + phase) % 8];
      uint64_t b = values[(i / bytes * 3 + phase / 2) % 8];
      memcpy(base + i, &a, bytes);
      memcpy(index + i, &b, bytes);
    }
    memset(got, 0x5a, sizeof(got));
    memset(native, 0x5a, sizeof(native));
    memset(scalar, 0x5a, sizeof(scalar));
    for (unsigned i = 0; i < vl; i += bytes) {
      uint64_t a = 0, b = 0;
      memcpy(&a, base + i, bytes);
      memcpy(&b, index + i, bytes);
      if (mode == 0 || mode == 1) {
        b &= UINT64_C(0xffffffff);
        if (mode == 0 && (b & UINT64_C(0x80000000))) b |= UINT64_C(0xffffffff00000000);
      }
      uint64_t value = a + (b << shift);
      memcpy(scalar + i, &value, bytes);
    }
    native_instruction(base, index, native);
    translated(base, index, got);
    if (memcmp(got, native, sizeof(got)) || memcmp(got, scalar, sizeof(got))) {
      fprintf(stderr, "%s: vl=%u phase=%u\n", name, vl, phase);
      return 1;
    }
  }
  return 0;
}
`
