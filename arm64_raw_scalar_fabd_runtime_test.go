package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func arm64ScalarABDMulRuntime(t *testing.T, triple string) (string, string) {
	t.Helper()
	var source, oracle, checks strings.Builder
	sigs := make(map[string]FuncSig)
	oracle.WriteString("#include <stdint.h>\n#include <string.h>\n")
	widths := []struct {
		bits                  int
		letter, ctype, values string
		fabd, fmulx           uint32
	}{
		{16, "h", "_Float16", "0,0x8000,0x3c00,0xbc00,1,0x03ff,0x7bff,0x7c00,0xfc00,0x7e55,0x7d11", 0x7ec01400, 0x5e401c00},
		{32, "s", "float", "0,0x80000000,0x3f800000,0xbf800000,1,0x007fffff,0x7f7fffff,0x7f800000,0xff800000,0x7fc05555,0x7f800111", 0x7ea0d400, 0x5e20dc00},
		{64, "d", "double", "0,0x8000000000000000ULL,0x3ff0000000000000ULL,0xbff0000000000000ULL,1,0x000fffffffffffffULL,0x7fefffffffffffffULL,0x7ff0000000000000ULL,0xfff0000000000000ULL,0x7ff8000000005555ULL,0x7ff0000000000111ULL", 0x7ee0d400, 0x5e60dc00},
	}
	for _, width := range widths {
		for _, op := range []string{"fabd", "fmulx"} {
			base := width.fabd
			if op == "fmulx" {
				base = width.fmulx
			}
			name := fmt.Sprintf("%s%d", op, width.bits)
			fmt.Fprintf(&source, `TEXT %s(SB),$0-24
MOVD a+0(FP),R0
MOVD b+8(FP),R1
MOVD out+16(FP),R2
VLD1 (R0),[V1.B16]
VLD1 (R1),[V2.B16]
WORD $%#08x
VST1 [V0.B16],(R2)
RET
`, name, base|2<<16|1<<5)
			sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
			}}}
			fmt.Fprintf(&oracle, `extern void %s(const void *, const void *, void *);
static int check_%s(void) {
  const uint%d_t bits[] = {%s};
  for (unsigned i = 0; i < sizeof(bits)/sizeof(bits[0]); i++) {
    for (unsigned j = 0; j < sizeof(bits)/sizeof(bits[0]); j++) {
      unsigned char a[16] = {0}, b[16] = {0}, got[16], want[16] = {0};
      %s x, y, result;
      memcpy(a, &bits[i], sizeof(x));
      memcpy(b, &bits[j], sizeof(y));
      memcpy(&x, a, sizeof(x));
      memcpy(&y, b, sizeof(y));
      __asm__ volatile("%s %%%s0, %%%s1, %%%s2" : "=w"(result) : "w"(x), "w"(y));
      memcpy(want, &result, sizeof(result));
      %s(a, b, got);
      if (memcmp(got, want, sizeof(got)) != 0) return 1;
    }
  }
  return 0;
}
`, name, name, width.bits, width.values, width.ctype, op, width.letter, width.letter, width.letter, name)
			fmt.Fprintf(&checks, "  if (check_%s()) return %d;\n", name, len(sigs))
		}
	}
	oracle.WriteString("int main(void) {\n" + checks.String() + "  return 0;\n}\n")
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	return ir, oracle.String()
}

func TestARM64RawScalarABDMulNativeRuntime(t *testing.T) {
	if runtime.GOARCH != "arm64" || runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("native ARM64 execution has a required Linux QEMU counterpart")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir, main := arm64ScalarABDMulRuntime(t, triple)
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang, "-march=armv8.2-a+fp16"}, "scalar_abd_mul", triple, ir, main, nil)
}
