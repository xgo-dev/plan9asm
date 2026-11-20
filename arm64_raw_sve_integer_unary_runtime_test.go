package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func testARM64RawSVEIntegerUnaryRuntime(t *testing.T, llc string) {
	var source, declarations, checks strings.Builder
	sigs := make(map[string]FuncSig)
	cases := arm64RawSVEUnaryCompleteCases()
	aliases := make(map[Op]bool)
	for _, form := range cases {
		if !aliases[form.op] {
			aliases[form.op] = true
			form.assembly = strings.ReplaceAll(form.assembly, "z0.", "z30.")
			form.reference = strings.ReplaceAll(form.reference, "z0.", "z30.")
			cases = append(cases, form)
		}
	}
	for _, form := range cases {
		// QEMU 8 cannot execute SVE2.1 REVD. Its two forms retain required
		// independent encoding and three-platform object checks.
		if form.op == "ZREVD" {
			continue
		}
		name := fmt.Sprintf("integer_unary_%d", len(sigs))
		destination := "z0"
		if strings.Fields(form.assembly)[1] == "z30."+strings.ToLower(form.width)+"," {
			destination = "z30"
		}
		native := []string{
			"ptrue p0.b",
			"ld1b { z0.b }, p0/z, [x0]",
			"ld1b { z30.b }, p0/z, [x1]",
			"ld1b { z1.b }, p0/z, [x2]",
			"cmpne p7.b, p0/z, z1.b, #0",
			form.assembly,
			"st1b { " + destination + ".b }, p0, [x3]",
		}
		fmt.Fprintf(&source, "TEXT %s(SB),$0-32\nMOVD a+0(FP),R0\nMOVD b+8(FP),R1\nMOVD mask+16(FP),R2\nMOVD out+24(FP),R3\n", name)
		for _, word := range assembleARM64LLVMWords(t, native, "+sve2p2") {
			fmt.Fprintf(&source, "WORD $%#08x\n", word)
		}
		source.WriteString("RET\n")
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: -1},
			{Offset: 8, Type: Ptr, Index: 1, Field: -1},
			{Offset: 16, Type: Ptr, Index: 2, Field: -1},
			{Offset: 24, Type: Ptr, Index: 3, Field: -1},
		}}}
		fmt.Fprintf(&declarations, "extern void %s(const void *, const void *, const void *, void *);\n", name)
		native[5] = form.reference
		assembly := strings.NewReplacer("[x0]", "[%[a]]", "[x1]", "[%[b]]", "[x2]", "[%[mask]]", "[x3]", "[%[out]]").Replace(strings.Join(native, "\\n\\t"))
		fmt.Fprintf(&checks, `    {
      const uint64_t samples[] = {0, 1, ~0ULL, 0x8080808080808080ULL,
        0x8000800080008000ULL, 0x8000000080000000ULL, 0x8000000000000000ULL,
        0x7f7f7f7f7f7f7f7fULL, 0x7fff7fff7fff7fffULL, 0x7fffffff7fffffffULL,
        0x7fffffffffffffffULL, 0xaaaaaaaaaaaaaaaaULL, 0x5555555555555555ULL};
      unsigned char a[256], b[256], mask[256], got[256], want[256];
      for (unsigned pattern = 0; pattern < 15; pattern++) {
        for (unsigned i = 0; i < sizeof(a); i++) {
          a[i] = (i * 17 + pattern * 29) %% 251 + 1;
          b[i] = samples[(i / 8 + pattern) %% 13] >> (8 * (i %% 8));
          mask[i] = pattern < 2 ? pattern : (i + pattern) %% 3;
        }
        memset(got, 0x5a, sizeof(got));
        memset(want, 0x5a, sizeof(want));
        __asm__ volatile("%s" :: [a]"r"(a), [b]"r"(b), [mask]"r"(mask), [out]"r"(want)
          : "p0", "p7", "z0", "z1", "z30", "memory");
        %s(a, b, mask, got);
        if (memcmp(got, want, sizeof(got)) != 0) {
          fprintf(stderr, "%s: vl=%%u pattern=%%u\n", vl, pattern);
          return %d;
        }
      }
    }
`, assembly, name, form.assembly, len(sigs))
	}
	// A vector-length change must not occur in a live SVE-compiled frame:
	// compiler-generated spills can use the previous length and corrupt it.
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
	t.Logf("checking %d unary forms and aliases across six SVE lengths", len(sigs))
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc", "-march=armv8.5-a+sve2"}, "raw_integer_unary", triple, ir, main,
		[]string{"qemu-aarch64", "-cpu", "max,sve-max-vq=16", "-L", "/usr/aarch64-linux-gnu"})
}
