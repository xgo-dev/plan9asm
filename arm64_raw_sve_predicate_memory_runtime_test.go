package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func testARM64RawSVEPredicateMemoryRuntime(t *testing.T, llc string) {
	var source, declarations, checks strings.Builder
	sigs := make(map[string]FuncSig)
	for i, offset := range []int{-256, -1, 0, 1, 255} {
		name := fmt.Sprintf("predicate_memory_%d", i)
		native := []string{
			fmt.Sprintf("ldr p15, [x0, #%d, mul vl]", offset),
			fmt.Sprintf("str p15, [x1, #%d, mul vl]", offset),
		}
		fmt.Fprintf(&source, "TEXT %s(SB),$0-16\nMOVD src+0(FP),R0\nMOVD dst+8(FP),R1\n", name)
		for _, word := range assembleARM64LLVMWords(t, native, "+sve") {
			fmt.Fprintf(&source, "WORD $%#08x\n", word)
		}
		source.WriteString("RET\n")
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: -1},
			{Offset: 8, Type: Ptr, Index: 1, Field: -1},
		}}}
		fmt.Fprintf(&declarations, "extern void %s(const void *, void *);\n", name)
		assembly := strings.NewReplacer("[x0,", "[%[src],", "[x1,", "[%[dst],").Replace(strings.Join(native, "\\n\\t"))
		fmt.Fprintf(&checks, `    {
      unsigned char source[16448], got[16448], want[16448], oracle[16448];
      for (unsigned phase = 0; phase < 4; phase++) {
        for (unsigned i = 0; i < sizeof(source); i++) source[i] = (i * 17 + phase * 83) & 255;
        memset(got, 0x5a, sizeof(got));
        memset(want, 0x5a, sizeof(want));
        memset(oracle, 0x5a, sizeof(oracle));
        unsigned position = 8192 + (%d) * (int)(vl / 8);
        memcpy(oracle + position, source + position, vl / 8);
        __asm__ volatile("%s" :: [src]"r"(source + 8192), [dst]"r"(want + 8192) : "p15", "memory");
        %s(source + 8192, got + 8192);
        if (memcmp(got, want, sizeof(got)) != 0 || memcmp(got, oracle, sizeof(got)) != 0) {
          fprintf(stderr, "%s: vl=%%u phase=%%u\n", vl, phase);
          return %d;
        }
      }
    }
`, offset, assembly, name, name, i+1)
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
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc", "-march=armv8.2-a+sve"}, "raw_predicate_memory", triple, ir, main,
		[]string{"qemu-aarch64", "-cpu", "max,sve-max-vq=16", "-L", "/usr/aarch64-linux-gnu"})
}
