package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func testARM64RawSVECompactRuntime(t *testing.T, llc string) {
	var source, declarations, checks strings.Builder
	sigs := make(map[string]FuncSig)
	// QEMU's baseline SVE covers S/D. B/H require SVE2.2 and have independent
	// assembler and object tests; they are not claimed as executed here.
	for _, width := range []struct {
		suffix string
		bytes  int
	}{{"s", 4}, {"d", 8}} {
		for _, destination := range []int{30, 31} {
			name := fmt.Sprintf("compact_%s_%d", width.suffix, destination)
			native := []string{
				"ptrue p0.b",
				"ld1b { z30.b }, p0/z, [x0]",
				"ld1b { z1.b }, p0/z, [x1]",
				fmt.Sprintf("cmpeq p7.%s, p0/z, z1.%s, #0", width.suffix, width.suffix),
				fmt.Sprintf("compact z%d.%s, p7, z30.%s", destination, width.suffix, width.suffix),
				fmt.Sprintf("st1b { z%d.b }, p0, [x2]", destination),
			}
			fmt.Fprintf(&source, "TEXT %s(SB),$0-24\nMOVD a+0(FP),R0\nMOVD b+8(FP),R1\nMOVD out+16(FP),R2\n", name)
			for _, word := range assembleARM64LLVMWords(t, native, "+sve") {
				fmt.Fprintf(&source, "WORD $%#08x\n", word)
			}
			source.WriteString("RET\n")
			sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
			}}}
			fmt.Fprintf(&declarations, "extern void %s(const void *, const void *, void *);\n", name)
			assembly := strings.NewReplacer("[x0]", "[%[a]]", "[x1]", "[%[b]]", "[x2]", "[%[out]]").Replace(strings.Join(native, "\\n\\t"))
			fmt.Fprintf(&checks, `    {
      const unsigned element = %d;
      for (unsigned pattern = 0; pattern < 12; pattern++) {
        unsigned char a[256], b[256] = {0}, got[256], want[256], oracle[256];
        for (unsigned i = 0; i < vl; i++) a[i] = (i * 17 + pattern * 43) %% 251 + 1;
        memset(got, 0x5a, sizeof(got));
        memset(want, 0x5a, sizeof(want));
        memset(oracle, 0x5a, sizeof(oracle));
        memset(oracle, 0, vl);
        unsigned count = 0;
        for (unsigned i = 0; i < vl / element; i++) {
          b[i * element] = pattern < 2 ? pattern : ((i * 17 + pattern) %% 7) < 3;
          if (b[i * element] == 0) {
            memcpy(oracle + count * element, a + i * element, element);
            count++;
          }
        }
        __asm__ volatile("%s" :: [a]"r"(a), [b]"r"(b), [out]"r"(want)
          : "p0", "p7", "z1", "z30", "z31", "memory");
        %s(a, b, got);
        if (memcmp(got, want, sizeof(got)) != 0 || memcmp(got, oracle, sizeof(got)) != 0) {
          fprintf(stderr, "%s: vl=%%u pattern=%%u\n", vl, pattern);
          return %d;
        }
      }
    }
`, width.bytes, assembly, name, name, len(sigs))
		}
	}
	main := arm64SVEVectorLengthMain(declarations.String(), checks.String())
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	const triple = "aarch64-unknown-linux-gnu"
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc", "-march=armv8.2-a+sve"}, "raw_compact", triple, ir, main,
		[]string{"qemu-aarch64", "-cpu", "max,sve-max-vq=16", "-L", "/usr/aarch64-linux-gnu"})
}
