package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func testARM64RawSVEPredicatePermuteRuntime(t *testing.T, llc string) {
	var source, declarations, checks strings.Builder
	sigs := make(map[string]FuncSig)
	// Observe every predicate bit, including inactive bits between wide elements.
	// Both source aliases are tested against the native instructions.
	for _, destination := range []int{15, 14, 13} {
		for _, form := range arm64RawPredicatePermuteForms(destination, 14, 13) {
			name := fmt.Sprintf("predicate_permute_%d", len(sigs))
			native := []string{
				"ptrue p0.b",
				"ld1b { z0.b }, p0/z, [x0]",
				"ld1b { z1.b }, p0/z, [x1]",
				"cmpeq p14.b, p0/z, z0.b, #0",
				"cmpeq p13.b, p0/z, z1.b, #0",
				form.assembly,
				"mov z0.b, #-1",
				"mov z1.b, #0",
				fmt.Sprintf("sel z0.b, p%d, z0.b, z1.b", destination),
				"st1b { z0.b }, p0, [x2]",
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
      unsigned char a[256], b[256], got[256], want[256];
      for (unsigned pattern = 0; pattern < 12; pattern++) {
        for (unsigned i = 0; i < vl; i++) {
          a[i] = pattern < 4 ? pattern & 1 : ((i * 17 + pattern) %% 7) < 3;
          b[i] = pattern < 4 ? pattern >> 1 : ((i * 11 + pattern) %% 9) < 5;
        }
        memset(got, 0x5a, sizeof(got));
        memset(want, 0x5a, sizeof(want));
        __asm__ volatile("%s" :: [a]"r"(a), [b]"r"(b), [out]"r"(want)
          : "p0", "p13", "p14", "p15", "z0", "z1", "memory");
        %s(a, b, got);
        if (memcmp(got, want, sizeof(got)) != 0) {
          fprintf(stderr, "%s: vl=%%u pattern=%%u\n", vl, pattern);
          return %d;
        }
      }
    }
`, assembly, name, form.assembly, len(sigs))
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
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc", "-march=armv8.2-a+sve"}, "raw_predicate_permute", triple, ir, main,
		[]string{"qemu-aarch64", "-cpu", "max,sve-max-vq=16", "-L", "/usr/aarch64-linux-gnu"})
}
