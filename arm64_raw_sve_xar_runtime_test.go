package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func testARM64RawSVEXARRuntime(t *testing.T, llc string) {
	var source, declarations, checks strings.Builder
	sigs := make(map[string]FuncSig)
	for size, width := range "bhsd" {
		bits := 8 << size
		for _, shift := range []int{1, bits / 2, bits - 1, bits} {
			for _, destination := range []int{30, 31} {
				name := fmt.Sprintf("xar_%d", len(sigs))
				native := []string{
					"ptrue p0.b",
					"ld1b { z30.b }, p0/z, [x0]",
					"ld1b { z31.b }, p0/z, [x1]",
					fmt.Sprintf("xar z%d.%c, z%d.%c, z30.%c, #%d", destination, width, destination, width, width, shift),
					fmt.Sprintf("st1b { z%d.b }, p0, [x2]", destination),
				}
				fmt.Fprintf(&source, "TEXT %s(SB),$0-24\nMOVD a+0(FP),R0\nMOVD b+8(FP),R1\nMOVD out+16(FP),R2\n", name)
				for _, word := range assembleARM64LLVMWords(t, native, "+sve2") {
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
				first := "b"
				if destination == 30 {
					first = "a"
				}
				fmt.Fprintf(&checks, `    {
      unsigned char a[256], b[256], got[256], native[256], scalar[256];
      const unsigned bytes = %d, bits = %d, rotation = %d %% bits;
      for (unsigned phase = 0; phase < 12; phase++) {
        for (unsigned i = 0; i < sizeof(a); i++) {
          a[i] = phase < 2 ? 255 * phase : i * 17 + phase * 83;
          b[i] = phase < 2 ? 255 * (1 - phase) : i * 59 + phase * 23;
        }
        memset(got, 0x5a, sizeof(got));
        memset(native, 0x5a, sizeof(native));
        memset(scalar, 0x5a, sizeof(scalar));
        for (unsigned i = 0; i < vl; i += bytes) {
          uint64_t first = 0, second = 0;
          memcpy(&first, %s + i, bytes);
          memcpy(&second, a + i, bytes);
          uint64_t value = first ^ second;
          if (rotation) value = (value >> rotation) | (value << (bits - rotation));
          memcpy(scalar + i, &value, bytes);
        }
        __asm__ volatile("%s" :: [a]"r"(a), [b]"r"(b), [out]"r"(native)
          : "p0", "z30", "z31", "memory");
        %s(a, b, got);
        if (memcmp(got, native, sizeof(got)) || memcmp(got, scalar, sizeof(got))) {
          fprintf(stderr, "%s: vl=%%u phase=%%u\n", vl, phase);
          return %d;
        }
      }
    }
`, bits/8, bits, shift, first, assembly, name, name, len(sigs))
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
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc", "-march=armv8.2-a+sve2"}, "raw_xar", triple, ir, main,
		[]string{"qemu-aarch64", "-cpu", "max,sve-max-vq=16", "-L", "/usr/aarch64-linux-gnu"})
}
