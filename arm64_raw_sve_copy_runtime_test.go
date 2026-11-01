package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func testARM64RawSVECopyRuntime(t *testing.T, llc string) {
	var source, declarations, checks strings.Builder
	sigs := make(map[string]FuncSig)
	for _, form := range arm64RawSVECopyForms() {
		// SP is validated as an operand, not compared between different frames.
		if strings.HasSuffix(form, "sp") {
			continue
		}
		name := fmt.Sprintf("copy_%d", len(sigs))
		form = strings.NewReplacer("w30", "w10", "x30", "x10").Replace(form)
		native := []string{
			"ptrue p0.b",
			"ld1b { z31.b }, p0/z, [x0]",
			"ld1b { z30.b }, p0/z, [x1]",
			"ldr x10, [x1]",
			"ld1b { z1.b }, p0/z, [x2]",
			"cmpne p7.b, p0/z, z1.b, #0",
			"orr p15.b, p0/z, p7.b, p7.b",
			form,
			"st1b { z31.b }, p0, [x3]",
		}
		fmt.Fprintf(&source, "TEXT %s(SB),$0-32\nMOVD a+0(FP),R0\nMOVD b+8(FP),R1\nMOVD mask+16(FP),R2\nMOVD out+24(FP),R3\n", name)
		for _, word := range assembleARM64LLVMWords(t, native, "+sve") {
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
		assembly := strings.NewReplacer("[x0]", "[%[a]]", "[x1]", "[%[b]]", "[x2]", "[%[mask]]", "[x3]", "[%[out]]").Replace(strings.Join(native, "\\n\\t"))
		fmt.Fprintf(&checks, `    {
      unsigned char a[256], b[256], mask[256], got[256], want[256];
      for (unsigned pattern = 0; pattern < 8; pattern++) {
        for (unsigned i = 0; i < sizeof(a); i++) {
          a[i] = (i * 17 + pattern * 29) %% 251 + 1;
          b[i] = (i * 31 + pattern * 131) & 255;
          mask[i] = pattern < 2 ? pattern : (i + pattern) %% 3;
        }
        memset(got, 0x5a, sizeof(got));
        memset(want, 0x5a, sizeof(want));
        __asm__ volatile("%s" :: [a]"r"(a), [b]"r"(b), [mask]"r"(mask), [out]"r"(want)
          : "p0", "p7", "p15", "z1", "z30", "z31", "x10", "memory");
        %s(a, b, mask, got);
        if (memcmp(got, want, sizeof(got)) != 0) {
          fprintf(stderr, "%s: vl=%%u pattern=%%u\n", vl, pattern);
          return %d;
        }
      }
    }
`, assembly, name, form, len(sigs))
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
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc", "-march=armv8.2-a+sve"}, "raw_copy", triple, ir, main,
		[]string{"qemu-aarch64", "-cpu", "max,sve-max-vq=16", "-L", "/usr/aarch64-linux-gnu"})
}
