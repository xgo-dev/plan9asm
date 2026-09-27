package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateX86MaskToVectorMoveCompleteForms(t *testing.T) {
	for _, target := range []struct {
		name, goarch, triple string
	}{
		{"darwin-amd64", "amd64", "x86_64-apple-darwin"},
		{"linux-amd64", "amd64", "x86_64-unknown-linux-gnu"},
		{"windows-amd64", "amd64", "x86_64-pc-windows-msvc"},
		{"linux-386", "386", "i386-unknown-linux-gnu"},
		{"windows-386", "386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT maskvectorforms(SB),$0-0\n")
			index := 0
			for _, lane := range []string{"B", "W", "D", "Q"} {
				for _, width := range []string{"X", "Y", "Z"} {
					vector := index%7 + 1
					mask := index % 8
					fmt.Fprintf(&source, "\tVPMOVM2%s K%d, %s%d\n", lane, mask, width, vector)
					fmt.Fprintf(&source, "\tVPMOV%s2M %s%d, K%d\n", lane, width, vector, mask)
					index++
				}
			}
			source.WriteString("\tRET\n")
			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: target.goarch, TargetTriple: target.triple, Sigs: map[string]FuncSig{"maskvectorforms": {Name: "maskvectorforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, fmt.Sprintf("mask-to-vector-%s.ll", target.name), fmt.Sprintf("mask-to-vector-%s.o", target.name), ir)
		})
	}
}

func TestTranslateX86MaskVectorMoveRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VPMOVM2B X0, X1",
		"VPMOVM2W K0, 0(AX)",
		"VPMOVM2D.Z K0, Z1",
		"VPMOVM2Q K8, Z1",
		"VPMOVB2M K0, K1",
		"VPMOVW2M 0(AX), K1",
		"VPMOVD2M.Z Z0, K1",
		"VPMOVQ2M Z0, K8",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			for _, goarch := range []string{"amd64", "386"} {
				source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
				requireX86GoAssemblerResult(t, goarch, source, false)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					continue
				}
				triple := "x86_64-unknown-linux-gnu"
				if goarch == "386" {
					triple = "i386-unknown-linux-gnu"
				}
				if _, err := Translate(file, Options{Goarch: goarch, TargetTriple: triple, Sigs: map[string]FuncSig{"bad": {Name: "bad", Ret: Void}}}); err == nil {
					t.Fatalf("Translate accepted %s %q outside Go 1.27's mask/vector move table", goarch, instruction)
				}
			}
		})
	}
}

func TestAMD64MaskVectorMoveRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test only runs on amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT maskVectorMoves(SB),NOSPLIT,$0-16
	MOVQ out+0(FP), AX
	KMOVQ mask+8(FP), K1
	VPMOVM2B K1, Z0
	VPMOVB2M Z0, K2
	KMOVQ K2, 0(AX)
	VPMOVM2W K1, Z1
	VPMOVW2M Z1, K3
	KMOVQ K3, 8(AX)
	VPMOVM2D K1, Z2
	VPMOVD2M Z2, K4
	KMOVQ K4, 16(AX)
	VPMOVM2Q K1, Z3
	VPMOVQ2M Z3, K5
	KMOVQ K5, 24(AX)
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	frame := FrameLayout{Params: []FrameSlot{
		{Offset: 0, Type: Ptr, Index: 0, Field: -1},
		{Offset: 8, Type: I64, Index: 1, Field: -1},
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
			"maskVectorMoves": {Name: "maskVectorMoves", Args: []LLVMType{Ptr, I64}, Ret: Void, Frame: frame},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void maskVectorMoves(uint64_t *, uint64_t);
int main(void) {
  uint64_t out[4] = {0};
  uint64_t mask = 0xd6a539c7f04b821dULL;
  maskVectorMoves(out, mask);
  if (out[0] != mask) return 1;
  if (out[1] != (mask & 0xffffffffULL)) return 2;
  if (out[2] != (mask & 0xffffULL)) return 3;
  if (out[3] != (mask & 0xffULL)) return 4;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "mask_vector_moves", triple, ll, mainC, runPrefix)
}
