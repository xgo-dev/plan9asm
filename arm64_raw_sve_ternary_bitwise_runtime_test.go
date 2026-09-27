package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func testARM64RawSVETernaryBitwiseRuntime(t *testing.T, llc string) {
	var source, declarations, checks strings.Builder
	sigs := make(map[string]FuncSig)
	for _, op := range []string{"bcax", "bsl", "bsl1n", "bsl2n", "eor3", "nbsl"} {
		for _, registers := range [][2]int{{30, 29}, {31, 29}, {30, 31}, {30, 30}, {31, 31}} {
			name := fmt.Sprintf("ternary_%d", len(sigs))
			native := []string{
				"ptrue p0.b", "ld1b { z31.b }, p0/z, [x0]", "ld1b { z30.b }, p0/z, [x1]",
				"ld1b { z29.b }, p0/z, [x2]", arm64RawSVETernaryAssembly(op, 31, registers[0], registers[1]),
				"st1b { z31.b }, p0, [x3]",
			}
			fmt.Fprintf(&source, "TEXT %s(SB),$0-32\nMOVD a+0(FP),R0\nMOVD b+8(FP),R1\nMOVD c+16(FP),R2\nMOVD out+24(FP),R3\n", name)
			for _, word := range assembleARM64LLVMWords(t, native, "+sve2") {
				fmt.Fprintf(&source, "WORD $%#08x\n", word)
			}
			source.WriteString("RET\n")
			sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1}, {Offset: 24, Type: Ptr, Index: 3, Field: -1},
			}}}
			fmt.Fprintf(&declarations, "extern void %s(const void *, const void *, const void *, void *);\n", name)
			assembly := strings.NewReplacer("[x0]", "[%[a]]", "[x1]", "[%[b]]", "[x2]", "[%[c]]", "[x3]", "[%[out]]").Replace(strings.Join(native, "\\n\\t"))
			second := map[int]string{31: "a", 30: "b"}[registers[0]]
			third := map[int]string{31: "a", 30: "b", 29: "c"}[registers[1]]
			expression := map[string]string{
				"bcax": "x ^ (y & ~z)", "eor3": "x ^ y ^ z",
				"bsl": "(x & z) | (y & ~z)", "bsl1n": "(~x & z) | (y & ~z)",
				"bsl2n": "(x & z) | (~y & ~z)", "nbsl": "~((x & z) | (y & ~z))",
			}[op]
			fmt.Fprintf(&checks, `    {
      unsigned char a[256], b[256], c[256], got[256], native[256], scalar[256];
      for (unsigned phase = 0; phase < 16; phase++) {
        for (unsigned i = 0; i < sizeof(a); i++) {
          a[i] = phase < 8 ? ((phase & 1) ? 0xff : 0) : i * 71 + phase * 83;
          b[i] = phase < 8 ? ((phase & 2) ? 0xff : 0) : i * 17 + phase * 51;
          c[i] = phase < 8 ? ((phase & 4) ? 0xff : 0) : i * 59 + phase * 29;
        }
        memset(got, 0x5a, sizeof(got));
        memset(native, 0x5a, sizeof(native));
        memset(scalar, 0x5a, sizeof(scalar));
        for (unsigned i = 0; i < vl; i++) {
          unsigned x = a[i], y = %s[i], z = %s[i];
          scalar[i] = %s;
        }
        __asm__ volatile("%s" :: [a]"r"(a), [b]"r"(b), [c]"r"(c), [out]"r"(native)
          : "p0", "z29", "z30", "z31", "memory");
        %s(a, b, c, got);
        if (memcmp(got, native, sizeof(got)) || memcmp(got, scalar, sizeof(got))) {
          fprintf(stderr, "%s: vl=%%u phase=%%u\n", vl, phase);
          return %d;
        }
      }
    }
`, second, third, expression, assembly, name, name, len(sigs))
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
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc", "-march=armv8.2-a+sve2"}, "raw_ternary", triple, ir, main,
		[]string{"qemu-aarch64", "-cpu", "max,sve-max-vq=16", "-L", "/usr/aarch64-linux-gnu"})
}
