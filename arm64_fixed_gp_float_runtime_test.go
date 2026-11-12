package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func arm64FixedGPFloatRuntime(t *testing.T, triple string) (string, string) {
	var source, declarations, checks strings.Builder
	sigs := make(map[string]FuncSig)
	for _, op := range []string{"scvtf", "ucvtf"} {
		for _, integerBits := range []int{32, 64} {
			for _, floatBits := range []int{32, 64} {
				for _, fractionalBits := range []int{1, integerBits / 2, integerBits} {
					name := fmt.Sprintf("%s_%d_%d_%d", op, integerBits, floatBits, fractionalBits)
					gp := map[int]string{32: "w", 64: "x"}[integerBits]
					fp := map[int]string{32: "s", 64: "d"}[floatBits]
					instruction := fmt.Sprintf("%s %s31, %s0, #%d", op, fp, gp, fractionalBits)
					word := assembleARM64LLVMWords(t, []string{instruction}, "")[0]
					fmt.Fprintf(&source, "TEXT %s(SB),$0-16\nMOVD input+0(FP),R0\nMOVD out+8(FP),R1\nWORD $%#08x\nVST1 [V31.B16],(R1)\nRET\n", name, word)
					sigs[name] = FuncSig{Name: name, Args: []LLVMType{I64, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
						{Offset: 0, Type: I64, Index: 0, Field: -1},
						{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					}}}
					fmt.Fprintf(&declarations, "extern void %s(uint64_t, void *);\n", name)
					oracle := fmt.Sprintf("%s %s31, %%%s[input], #%d\\n\\tstr q31, [%%[out]]", op, fp, gp, fractionalBits)
					fmt.Fprintf(&checks, `    {
      unsigned char got[16], want[16];
      memset(got, 0xff, sizeof(got));
      __asm__ volatile("%s" :: [input]"r"(input), [out]"r"(want) : "v31", "memory");
      %s(input, got);
      if (memcmp(got, want, sizeof(got))) return %d;
    }
`, oracle, name, len(sigs))
				}
			}
		}
	}
	main := "#include <stdint.h>\n#include <string.h>\n" + declarations.String() + `
int main(void) {
  const uint64_t inputs[] = {0, 1, UINT64_MAX, 0x8000000000000000ULL,
    0x7fffffffffffffffULL, 0x80000000, 0xffffffff, 0x01000001,
    0x0123456789abcdefULL, 0x76543210fedcba98ULL};
  for (unsigned i = 0; i < sizeof(inputs)/sizeof(inputs[0]); i++) {
    uint64_t input = inputs[i];
` + checks.String() + "  }\n  return 0;\n}\n"
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	return ir, main
}

func TestARM64FixedGPFloatRuntime(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, main := arm64FixedGPFloatRuntime(t, triple)
			compileLLVMToObject(t, llc, triple, "fixed_gp.ll", "fixed_gp.o", ir)
			native := runtime.GOOS == "darwin" && triple == "aarch64-apple-darwin" ||
				runtime.GOOS == "linux" && triple == "aarch64-unknown-linux-gnu"
			if runtime.GOARCH == "arm64" && native {
				compileAndRunRuntimeTestForTarget(t, llc, clang, "fixed_gp", triple, ir, main, nil)
			}
		})
	}
}
