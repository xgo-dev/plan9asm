package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func testARM64RawSVEStructuredMemoryRuntime(t *testing.T, llc string) {
	var source, declarations, checks strings.Builder
	sigs := make(map[string]FuncSig)
	for _, form := range arm64RawSVEStructuredCases() {
		if form.width == "q" { // SVE2.1 Q forms have object checks; QEMU 8 lacks them.
			continue
		}
		for _, indexed := range []bool{false, true} {
			name := fmt.Sprintf("structure_%d", len(sigs))
			native := []string{"ptrue p0.b", "ld1b { z20.b }, p0/z, [x2]", "cmpne p7.b, p0/z, z20.b, #0"}
			if !form.load {
				for i := 0; i < form.count; i++ {
					native = append(native, fmt.Sprintf("ld1b { z%d.b }, p0/z, [x0, #%d, mul vl]", (31+i)%32, i))
				}
			}
			base := "x1"
			if form.load {
				base = "x0"
			}
			address := fmt.Sprintf("[%s, #%d, mul vl]", base, form.count)
			if indexed {
				address = fmt.Sprintf("[%s, x4, lsl #%d]", base, form.shift)
			}
			native = append(native, form.assembly(31, 7, address))
			if form.load {
				for i := 0; i < form.count; i++ {
					native = append(native, fmt.Sprintf("st1b { z%d.b }, p0, [x1, #%d, mul vl]", (31+i)%32, i))
				}
			}
			fmt.Fprintf(&source, "TEXT %s(SB),$0-32\nMOVD src+0(FP),R0\nMOVD dst+8(FP),R1\nMOVD mask+16(FP),R2\nMOVD index+24(FP),R4\n", name)
			for _, word := range assembleARM64LLVMWords(t, native, "+sve") {
				fmt.Fprintf(&source, "WORD $%#08x\n", word)
			}
			source.WriteString("RET\n")
			sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				{Offset: 24, Type: I64, Index: 3, Field: -1},
			}}}
			fmt.Fprintf(&declarations, "extern void %s(const void *, void *, const void *, int64_t);\n", name)
			assembly := strings.NewReplacer("[x0", "[%[src]", "[x1", "[%[dst]", "[x2", "[%[mask]", "x4", "%[index]").Replace(strings.Join(native, "\\n\\t"))
			load := 0
			if form.load {
				load = 1
			}
			fmt.Fprintf(&checks, `    {
      unsigned char input[12288], got[12288], want[12288], mask[256];
      for (unsigned phase = 0; phase < 8; phase++) {
        for (unsigned i = 0; i < sizeof(input); i++) input[i] = (i * 17 + phase * 83) & 255;
        for (unsigned i = 0; i < sizeof(mask); i++) mask[i] = phase < 2 ? phase : (i + phase) %% 3;
        memset(got, 0x5a, sizeof(got));
        memset(want, 0x5a, sizeof(want));
        const int64_t offsets[] = {-3, 0, 5};
        int64_t index = offsets[phase %% 3];
        const void *src = phase == 0 && %d ? NULL : input + 4096;
        void *dst = phase == 0 && !%d ? NULL : want + 4096;
        __asm__ volatile("%s" :: [src]"r"(src), [dst]"r"(dst), [mask]"r"(mask), [index]"r"(index)
          : "p0", "p7", "z31", "z0", "z1", "z2", "z20", "memory");
        %s(src, phase == 0 && !%d ? NULL : got + 4096, mask, index);
        if (memcmp(got, want, sizeof(got)) != 0) {
          fprintf(stderr, "%s indexed=%t: vl=%%u phase=%%u\n", vl, phase);
          return %d;
        }
      }
    }
`, load, load, assembly, name, load, form.op, indexed, len(sigs))
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
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc", "-march=armv8.2-a+sve"}, "raw_structure", triple, ir, main,
		[]string{"qemu-aarch64", "-cpu", "max,sve-max-vq=16", "-L", "/usr/aarch64-linux-gnu"})
}
