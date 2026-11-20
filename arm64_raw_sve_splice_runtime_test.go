package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func testARM64RawSVESpliceRuntime(t *testing.T, llc string) {
	var source, declarations, checks strings.Builder
	sigs := make(map[string]FuncSig)
	type spliceForm struct {
		constructive               bool
		first, second, destination int
	}
	forms := []spliceForm{{false, 31, 0, 31}, {false, 31, 31, 31}}
	for _, first := range []int{0, 31} {
		for _, destination := range []int{first, (first + 1) % 32, 15} {
			forms = append(forms, spliceForm{true, first, (first + 1) % 32, destination})
		}
	}
	for size, width := range "bhsd" {
		for _, form := range forms {
			name := fmt.Sprintf("splice_%d", len(sigs))
			native := []string{
				"ptrue p0.b", "ld1b { z20.b }, p0/z, [x2]", "cmpne p7.b, p0/z, z20.b, #0",
				fmt.Sprintf("ld1b { z%d.b }, p0/z, [x0]", form.first),
			}
			second := "a"
			if form.first != form.second {
				native = append(native, fmt.Sprintf("ld1b { z%d.b }, p0/z, [x1]", form.second))
				second = "b"
			}
			encodedSource := form.second
			if form.constructive {
				encodedSource = form.first
			}
			native = append(native, arm64RawSVESpliceAssembly(form.constructive, width, form.destination, encodedSource, 7),
				fmt.Sprintf("st1b { z%d.b }, p0, [x3]", form.destination))
			fmt.Fprintf(&source, "TEXT %s(SB),$0-32\nMOVD a+0(FP),R0\nMOVD b+8(FP),R1\nMOVD mask+16(FP),R2\nMOVD out+24(FP),R3\n", name)
			for _, word := range assembleARM64LLVMWords(t, native, "+sve2") {
				fmt.Fprintf(&source, "WORD $%#08x\n", word)
			}
			source.WriteString("RET\n")
			sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1}, {Offset: 24, Type: Ptr, Index: 3, Field: -1},
			}}}
			fmt.Fprintf(&declarations, "extern void %s(const void *, const void *, const void *, void *);\n", name)
			assembly := strings.NewReplacer("[x0]", "[%[a]]", "[x1]", "[%[b]]", "[x2]", "[%[mask]]", "[x3]", "[%[out]]").Replace(strings.Join(native, "\\n\\t"))
			fmt.Fprintf(&checks, `    {
      unsigned char a[256], b[256], mask[256], got[256], native[256], scalar[256];
      const unsigned element = %d;
      for (unsigned phase = 0; phase < 12; phase++) {
        for (unsigned i = 0; i < sizeof(a); i++) {
          a[i] = i * 17 + phase * 83;
          b[i] = i * 59 + phase * 23;
          mask[i] = phase < 2 ? phase : (i / element + phase * 3) %% 7 == 0;
        }
        memset(got, 0x5a, sizeof(got));
        memset(native, 0x5a, sizeof(native));
        memset(scalar, 0x5a, sizeof(scalar));
        int first = -1, last = -1;
        for (unsigned i = 0; i < vl / element; i++) {
          if (mask[i * element]) {
            if (first < 0) first = i;
            last = i;
          }
        }
        unsigned count = first < 0 ? 0 : (last - first + 1) * element;
        if (count) memcpy(scalar, a + first * element, count);
        memcpy(scalar + count, %s, vl - count);
        __asm__ volatile("%s" :: [a]"r"(a), [b]"r"(b), [mask]"r"(mask), [out]"r"(native)
          : "p0", "p7", "z0", "z1", "z15", "z20", "z31", "memory");
        %s(a, b, mask, got);
        if (memcmp(got, native, sizeof(got)) || memcmp(got, scalar, sizeof(got))) {
          fprintf(stderr, "%s: vl=%%u phase=%%u\n", vl, phase);
          return %d;
        }
      }
    }
`, 1<<size, second, assembly, name, name, len(sigs))
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
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc", "-march=armv8.2-a+sve2"}, "raw_splice", triple, ir, main,
		[]string{"qemu-aarch64", "-cpu", "max,sve-max-vq=16", "-L", "/usr/aarch64-linux-gnu"})
}
