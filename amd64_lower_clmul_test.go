package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateX86PackedCarrylessMultiplyCompleteGoAssemblerForms(t *testing.T) {
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			last := 15
			if target.goarch == "386" {
				last = 7
			}
			var source strings.Builder
			fmt.Fprintf(&source, "TEXT carrylessmultiplyforms(SB),NOSPLIT,$0-0\n\tPCLMULQDQ $0, X0, X%d\n\tPCLMULQDQ $255, 8(AX), X%d\n", last, last)
			if target.goarch == "amd64" {
				source.WriteString("\tVPCLMULQDQ $0, X0, X1, X2\n")
				source.WriteString("\tVPCLMULQDQ $1, 8(AX), X1, X2\n")
				source.WriteString("\tVPCLMULQDQ $16, Y0, Y1, Y2\n")
				source.WriteString("\tVPCLMULQDQ $17, 8(AX), Y1, Y2\n")
				source.WriteString("\tVPCLMULQDQ $127, Z0, Z1, Z2\n")
				source.WriteString("\tVPCLMULQDQ $128, 8(AX), Z1, Z2\n")
				source.WriteString("\tVPCLMULQDQ $255, X16, X31, X0\n")
			}
			source.WriteString("\tRET\n")
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"carrylessmultiplyforms": {Name: "carrylessmultiplyforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "packed-carryless-multiply-"+target.name+".ll", "packed-carryless-multiply-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86PackedCarrylessMultiplyRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"PCLMULQDQ $-1, X0, X1",
		"PCLMULQDQ $256, X0, X1",
		"PCLMULQDQ $1, X16, X1",
		"PCLMULQDQ $1, Y0, Y1",
		"PCLMULQDQ.Z $1, X0, X1",
		"PCLMULQDQ $1, X0, (AX)",
		"VPCLMULQDQ $-1, X0, X1, X2",
		"VPCLMULQDQ $256, X0, X1, X2",
		"VPCLMULQDQ $1, X0, Y1, Y2",
		"VPCLMULQDQ $1, X0, X1, K1, X2",
		"VPCLMULQDQ.Z $1, X0, X1, X2",
		"VPCLMULQDQ $1, X0, (AX), X2",
		"VPCLMULQDQ $1, X0, X1, (AX)",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86PackedCarrylessMultiplyRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	for _, instruction := range []string{
		"PCLMULQDQ $1, X8, X0",
		"PCLMULQDQ $1, X0, X8",
		"VPCLMULQDQ $1, X0, X1, X2",
	} {
		t.Run("386_"+strings.NewReplacer(" ", "_").Replace(instruction), func(t *testing.T) {
			assertX86PackedCarrylessMultiplyRejected(t, "386", "i386-unknown-linux-gnu", instruction)
		})
	}
}

func assertX86PackedCarrylessMultiplyRejected(t *testing.T, goarch, triple, instruction string) {
	t.Helper()
	file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
	if err == nil {
		_, err = Translate(file, Options{
			TargetTriple: triple,
			Goarch:       goarch,
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		})
	}
	if err == nil {
		t.Fatalf("Translate accepted %q outside Go 1.27's PCLMULQDQ/VPCLMULQDQ tables for %s", instruction, goarch)
	}
}

func TestAMD64PackedCarrylessMultiplyRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test only runs on amd64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	source := `
TEXT carrylessmultiply(SB),NOSPLIT,$0-24
	MOVQ out+0(FP), AX
	MOVQ a+8(FP), BX
	MOVQ b+16(FP), CX
	VMOVDQU (BX), Y0
	VMOVDQU (CX), Y1
	VPCLMULQDQ $0x10, Y0, Y1, Y2
	VMOVDQU Y2, (AX)
	VZEROUPPER
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	frame := FrameLayout{Params: []FrameSlot{
		{Offset: 0, Type: Ptr, Index: 0, Field: -1},
		{Offset: 8, Type: Ptr, Index: 1, Field: -1},
		{Offset: 16, Type: Ptr, Index: 2, Field: -1},
	}}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var runPrefix []string
	if crossRosetta {
		triple = "x86_64-apple-macosx"
		runPrefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "amd64",
		Sigs: map[string]FuncSig{
			"carrylessmultiply": {Name: "carrylessmultiply", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void, Frame: frame},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mainC := `
#include <stdint.h>
extern void carrylessmultiply(uint64_t *, const uint64_t *, const uint64_t *);
static void clmul(uint64_t a, uint64_t b, uint64_t *lo, uint64_t *hi) {
  uint64_t l = 0, h = 0;
  for (unsigned i = 0; i < 64; i++) if ((b >> i) & 1) {
    l ^= a << i;
    if (i) h ^= a >> (64-i);
  }
  *lo = l; *hi = h;
}
int main(void) {
  uint64_t a[4] = {0x123456789abcdef0ULL, 0xfedcba9876543210ULL, 0x1111222233334444ULL, 0x5555666677778888ULL};
  uint64_t b[4] = {0x0123456789abcdefULL, 0x0f1e2d3c4b5a6978ULL, 0x9999aaaabbbbccccULL, 0xddddeeeeffff0001ULL};
  uint64_t out[4] = {0}, want[4] = {0};
	clmul(b[0], a[1], &want[0], &want[1]);
	clmul(b[2], a[3], &want[2], &want[3]);
  carrylessmultiply(out, a, b);
  for (int i = 0; i < 4; i++) if (out[i] != want[i]) return 10+i;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "packed_carryless_multiply", triple, ll, mainC, runPrefix)
}
