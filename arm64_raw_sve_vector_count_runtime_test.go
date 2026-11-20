package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func testARM64RawSVEVectorCountRuntime(t *testing.T, llc string) {
	var source, declarations, checks strings.Builder
	declarations.WriteString(`
static uint64_t vector_count(unsigned pattern, unsigned lanes) {
  if (pattern == 31) return lanes;
  if (pattern == 30) return lanes / 3 * 3;
  if (pattern == 29) return lanes / 4 * 4;
  if (pattern == 0) {
    unsigned n = 1;
    while (n * 2 <= lanes) n *= 2;
    return n;
  }
  unsigned n = pattern <= 8 ? pattern : pattern <= 13 ? 1u << (pattern - 5) : 0;
  return n <= lanes ? n : 0;
}
`)
	sigs := make(map[string]FuncSig)
	for _, operation := range []string{"inc", "dec"} {
		for size := 1; size < 4; size++ {
			for pattern := 0; pattern < 32; pattern++ {
				name := fmt.Sprintf("vector_count_%d", len(sigs))
				multiplier := pattern%16 + 1
				native := []string{
					"ptrue p0.b", "ld1b { z31.b }, p0/z, [x0]",
					fmt.Sprintf("%s%c z31.%c, #%d, mul #%d", operation, "bhwd"[size], "bhsd"[size], pattern, multiplier),
					"st1b { z31.b }, p0, [x1]",
				}
				words := assembleARM64LLVMWords(t, native, "+sve")
				fmt.Fprintf(&source, "TEXT %s(SB),$0-16\nMOVD a+0(FP),R0\nMOVD out+8(FP),R1\n", name)
				for _, word := range words {
					fmt.Fprintf(&source, "WORD $%#08x\n", word)
				}
				source.WriteString("RET\n")
				sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1},
				}}}
				fmt.Fprintf(&declarations, "extern void %s(const void *, void *);\n", name)
				// Some GNU assembler versions reject unnamed predicate patterns.
				// Their encodings are legal and architecturally count zero.
				native[2] = fmt.Sprintf(".inst %#08x", words[2])
				assembly := strings.NewReplacer("[x0]", "[%[a]]", "[x1]", "[%[out]]").Replace(strings.Join(native, "\\n\\t"))
				operator := "+"
				if operation == "dec" {
					operator = "-"
				}
				fmt.Fprintf(&checks, `    {
      unsigned char a[256], got[256], native[256], scalar[256];
      const unsigned element = %d;
      uint64_t count = vector_count(%d, vl / element) * %d;
      for (unsigned phase = 0; phase < 8; phase++) {
        for (unsigned i = 0; i < sizeof(a); i++) {
          a[i] = phase == 0 ? 0xff : phase == 1 ? 0 : i * 71 + phase * 83;
        }
        memset(got, 0x5a, sizeof(got));
        memset(native, 0x5a, sizeof(native));
        memset(scalar, 0x5a, sizeof(scalar));
        for (unsigned i = 0; i < vl; i += element) {
          uint64_t value = 0;
          memcpy(&value, a + i, element);
          value = value %s count;
          memcpy(scalar + i, &value, element);
        }
        __asm__ volatile("%s" :: [a]"r"(a), [out]"r"(native) : "p0", "z31", "memory");
        %s(a, got);
        if (memcmp(got, native, sizeof(got)) || memcmp(got, scalar, sizeof(got))) {
          fprintf(stderr, "%s: vl=%%u phase=%%u\n", vl, phase);
          return %d;
        }
      }
    }
`, 1<<size, pattern, multiplier, operator, assembly, name, name, len(sigs))
			}
		}
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
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc", "-march=armv8.2-a+sve"}, "raw_vector_count", triple, ir, main,
		[]string{"qemu-aarch64", "-cpu", "max,sve-max-vq=16", "-L", "/usr/aarch64-linux-gnu"})
}
