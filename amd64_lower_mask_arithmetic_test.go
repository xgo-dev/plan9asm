package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateX86MaskArithmeticCompleteGoAssemblerForms(t *testing.T) {
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
			var source strings.Builder
			source.WriteString("TEXT maskArithmeticForms(SB),$0-0\n")
			for _, width := range []string{"B", "W", "D", "Q"} {
				fmt.Fprintf(&source, "\tKADD%s K0, K7, K3\n", width)
				fmt.Fprintf(&source, "\tKSHIFTL%s $0, K3, K4\n", width)
				fmt.Fprintf(&source, "\tKSHIFTR%s $255, K4, K7\n", width)
			}
			source.WriteString("\tRET\n")
			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"maskArithmeticForms": {Name: "maskArithmeticForms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "mask-arithmetic-"+target.name+".ll", "mask-arithmetic-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86MaskArithmeticRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"KADDB K1, K2",
		"KADDW K1, AX, K2",
		"KADDD K1, K2, K8",
		"KADDQ.Z K1, K2, K3",
		"KSHIFTLB K1, K2",
		"KSHIFTLW $-1, K1, K2",
		"KSHIFTLD $1, AX, K2",
		"KSHIFTRQ $1, K1, K8",
		"KSHIFTRB.Z $1, K1, K2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			for _, goarch := range []string{"amd64", "386"} {
				source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
				requireX86GoAssemblerResult(t, goarch, source, false)
				assertX86MaskArithmeticRejected(t, goarch, instruction)
			}
		})
	}
}

func assertX86MaskArithmeticRejected(t *testing.T, goarch, instruction string) {
	t.Helper()
	file, err := Parse(ArchAMD64, "TEXT bad(SB),$0-0\n\t"+instruction+"\n\tRET\n")
	if err != nil {
		return
	}
	triple := "x86_64-unknown-linux-gnu"
	if goarch == "386" {
		triple = "i386-unknown-linux-gnu"
	}
	if _, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       goarch,
		Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
	}); err == nil {
		t.Fatalf("Translate accepted %s %q outside Go 1.27's KADD/KSHIFT tables", goarch, instruction)
	}
}

func TestAMD64MaskArithmeticRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test only runs on amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT maskArithmetic(SB),$0-24
	MOVQ out+0(FP), AX
	KMOVQ a+8(FP), K1
	KMOVQ b+16(FP), K2
	KADDB K1, K2, K3
	KADDW K1, K2, K4
	KSHIFTLW $3, K1, K5
	KSHIFTRW $4, K2, K6
	KSHIFTRB $9, K2, K7
	KMOVQ K3, 0(AX)
	KMOVQ K4, 8(AX)
	KMOVQ K5, 16(AX)
	KMOVQ K6, 24(AX)
	KMOVQ K7, 32(AX)
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	frame := FrameLayout{Params: []FrameSlot{
		{Offset: 0, Type: Ptr, Index: 0, Field: -1},
		{Offset: 8, Type: I64, Index: 1, Field: -1},
		{Offset: 16, Type: I64, Index: 2, Field: -1},
	}}
	triple := "x86_64-apple-darwin"
	if runtime.GOOS != "darwin" {
		triple = testTargetTriple(runtime.GOOS, "amd64")
	}
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "amd64",
		Sigs: map[string]FuncSig{
			"maskArithmetic": {Name: "maskArithmetic", Args: []LLVMType{Ptr, I64, I64}, Ret: Void, Frame: frame},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void maskArithmetic(uint64_t *, uint64_t, uint64_t);
int main(void) {
  uint64_t out[5] = {0};
  uint64_t a = 0x123456789abcdef5ULL;
  uint64_t b = 0xfedcba98765432f0ULL;
  maskArithmetic(out, a, b);
  if (out[0] != ((a + b) & 0xff)) return 1;
  if (out[1] != ((a + b) & 0xffff)) return 2;
  if (out[2] != ((a & 0xffff) << 3 & 0xffff)) return 3;
  if (out[3] != ((b & 0xffff) >> 4)) return 4;
  if (out[4] != 0) return 5;
  return 0;
}
`
	var runPrefix []string
	if crossRosetta {
		runPrefix = []string{"arch", "-x86_64"}
	}
	compileAndRunRuntimeTestForTarget(t, llc, clang, "mask_arithmetic", triple, ll, mainC, runPrefix)
}
