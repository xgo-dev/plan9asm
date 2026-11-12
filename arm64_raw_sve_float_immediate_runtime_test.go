package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func testARM64RawSVEFloatImmediateRuntime(t *testing.T, llc string) {
	type runtimeCase struct {
		size, predicate int
		native          []string
	}
	var cases []runtimeCase
	var allNative []string
	for size := 1; size < 4; size++ {
		for _, predicate := range []int{-1, 0, 7, 8, 15} {
			native := []string{
				"ptrue p1.b", "ld1b { z30.b }, p1/z, [x0]",
				"ld1b { z28.b }, p1/z, [x1]", "cmpne p7.b, p1/z, z28.b, #0",
			}
			if predicate >= 0 {
				native = append(native, fmt.Sprintf("orr p%d.b, p1/z, p7.b, p7.b", predicate))
			}
			// Batch all immediates in one function, with sequential VL-sized
			// outputs. The complete domain needs only fifteen runtime functions.
			for imm := 0; imm < 256; imm++ {
				native = append(native, "mov z31.d, z30.d",
					arm64SVEFloatImmediateAssembly(size, 31, predicate, imm),
					"st1b { z31.b }, p1, [x2]", "addvl x2, x2, #1")
			}
			cases = append(cases, runtimeCase{size, predicate, native})
			allNative = append(allNative, native...)
		}
	}
	words := assembleARM64LLVMWords(t, allNative, "+sve")
	var source, declarations, checks strings.Builder
	declarations.WriteString(arm64SVEFloatImmediateRuntimeReference)
	sigs := make(map[string]FuncSig)
	for _, test := range cases {
		name := fmt.Sprintf("float_immediate_%d", len(sigs))
		fmt.Fprintf(&source, "TEXT %s(SB),$0-24\nMOVD a+0(FP),R0\nMOVD mask+8(FP),R1\nMOVD out+16(FP),R2\n", name)
		for _, word := range words[:len(test.native)] {
			fmt.Fprintf(&source, "WORD $%#08x\n", word)
		}
		words = words[len(test.native):]
		source.WriteString("RET\n")
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1},
			{Offset: 16, Type: Ptr, Index: 2, Field: -1},
		}}}
		assembly := strings.NewReplacer("x0", "%[a]", "x1", "%[mask]", "x2", "%[out]").Replace(strings.Join(test.native, "\\n\\t"))
		fmt.Fprintf(&declarations, `extern void %[1]s(const void *, const void *, void *);
static void %[1]s_native(const void *a, const void *mask, void *out) {
  __asm__ volatile("%[2]s" : [out]"+&r"(out) : [a]"r"(a), [mask]"r"(mask)
    : "p0", "p1", "p7", "p8", "p15", "z28", "z30", "z31", "memory");
}
`, name, assembly)
		predicated := 0
		if test.predicate >= 0 {
			predicated = 1
		}
		fmt.Fprintf(&checks, "  if (check_float_immediate(vl, %d, %d, %s, %s_native, %q)) return 1;\n",
			1<<test.size, predicated, name, name, name)
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
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc", "-march=armv8.2-a+sve"}, "raw_float_immediate", triple, ir, main,
		[]string{"qemu-aarch64", "-cpu", "max,sve-max-vq=16", "-L", "/usr/aarch64-linux-gnu"})
}

const arm64SVEFloatImmediateRuntimeReference = `
#include <math.h>
typedef void (*float_immediate_fn)(const void *, const void *, void *);
__attribute__((noinline, noclone))
static int check_float_immediate(unsigned vl, unsigned bytes, int predicated,
    float_immediate_fn translated, float_immediate_fn native_instruction, const char *name) {
  unsigned char a[256], mask[256];
  unsigned char got[256 * 256 + 32], native[sizeof(got)], scalar[sizeof(got)];
  for (unsigned phase = 0; phase < 8; phase++) {
    for (unsigned i = 0; i < sizeof(a); i++) {
      a[i] = i * 17 + phase * 29;
      mask[i] = phase < 2 ? phase : (i + phase) % 3 != 0;
    }
    memset(got, 0x5a, sizeof(got));
    memset(native, 0x5a, sizeof(native));
    memset(scalar, 0x5a, sizeof(scalar));
    for (unsigned imm = 0; imm < 256; imm++) {
      double value = ldexp(16 + (imm & 15), (int)(((imm >> 4) & 7) ^ 4) - 7);
      if (imm & 128) value = -value;
      unsigned char bits[8];
      if (bytes == 2) {
        __fp16 h = value;
        memcpy(bits, &h, bytes);
      } else if (bytes == 4) {
        float f = value;
        memcpy(bits, &f, bytes);
      } else {
        memcpy(bits, &value, bytes);
      }
      for (unsigned i = 0; i < vl; i += bytes) {
        memcpy(scalar + imm * vl + i, !predicated || mask[i] ? bits : a + i, bytes);
      }
    }
    native_instruction(a, mask, native);
    translated(a, mask, got);
    if (memcmp(got, native, sizeof(got)) || memcmp(got, scalar, sizeof(got))) {
      fprintf(stderr, "%s: vl=%u phase=%u translated/native=%d native/scalar=%d\n",
          name, vl, phase, memcmp(got, native, sizeof(got)), memcmp(native, scalar, sizeof(got)));
      return 1;
    }
  }
  return 0;
}
`
