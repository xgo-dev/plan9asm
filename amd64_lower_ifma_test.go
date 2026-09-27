package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateX86IFMACompleteGo127Forms(t *testing.T) {
	// VPMADD52HUQ/LUQ share Go 1.27's six-row _yvblendmpd table: X/Y/Z,
	// each with an unmasked and K1-K7 masked row. Their EVEX attributes add
	// scalar qword broadcast and zeroing.
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
			source.WriteString("TEXT ifma_forms(SB),$0-0\n")
			for _, op := range []string{"VPMADD52HUQ", "VPMADD52LUQ"} {
				for _, width := range []string{"X", "Y", "Z"} {
					fmt.Fprintf(&source, "\t%s %s0, %s1, %s2\n", op, width, width, width)
					fmt.Fprintf(&source, "\t%s 8(BX), %s3, %s4\n", op, width, width)
					fmt.Fprintf(&source, "\t%s.BCST 16(BX), %s5, %s6\n", op, width, width)
					if target.goarch == "amd64" {
						fmt.Fprintf(&source, "\t%s %s20, %s21, K1, %s22\n", op, width, width, width)
						fmt.Fprintf(&source, "\t%s.Z 24(BX), %s23, K7, %s24\n", op, width, width)
						fmt.Fprintf(&source, "\t%s.BCST.Z 32(BX), %s25, K2, %s26\n", op, width, width)
					}
				}
			}
			source.WriteString("\tRET\n")

			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs: map[string]FuncSig{
					"ifma_forms": {Name: "ifma_forms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "ifma-"+target.name+".ll", "ifma-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86IFMARejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"VPMADD52HUQ X0, X1",
		"VPMADD52LUQ X0, X1, X2, X3, X4",
		"VPMADD52HUQ Y0, X1, X2",
		"VPMADD52LUQ X0, Y1, X2",
		"VPMADD52HUQ X0, X1, Y2",
		"VPMADD52LUQ X0, 8(BX), X2",
		"VPMADD52HUQ X0, X1, 8(BX)",
		"VPMADD52LUQ X0, X1, K0, X2",
		"VPMADD52HUQ X0, K1, X1, X2",
		"VPMADD52LUQ.Z X0, X1, X2",
		"VPMADD52HUQ.BCST X0, X1, X2",
		"VPMADD52LUQ.BCST.Z 8(BX), X1, X2",
		"VPMADD52HUQ.Z.BCST 8(BX), X1, K1, X2",
		"VPMADD52LUQ.SAE X0, X1, X2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireX86GoAssemblerResult(t, "amd64", source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				Goarch:       "amd64",
				TargetTriple: "x86_64-unknown-linux-gnu",
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's IFMA table", instruction)
			}
		})
	}
	for _, instruction := range []string{
		"VPMADD52HUQ X0, X1, K1, X2",
		"VPMADD52LUQ.Z 8(BX), Y1, K7, Y2",
		"VPMADD52HUQ.BCST.Z 16(BX), Z1, K2, Z2",
		"VPMADD52LUQ Z8, Z0, Z1",
		"VPMADD52HUQ Z0, Z8, Z1",
		"VPMADD52LUQ Z0, Z1, Z8",
	} {
		t.Run("386_"+strings.NewReplacer(" ", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireX86GoAssemblerResult(t, "386", source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				Goarch:       "386",
				TargetTriple: "i386-unknown-linux-gnu",
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted 386 %q outside Go 1.27's IFMA frontend boundary", instruction)
			}
		})
	}
}

func TestAMD64IFMARuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test only runs on amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT ifmaSemantics(SB),$0-48
	MOVQ out+0(FP), AX
	MOVQ first+8(FP), BX
	MOVQ second+16(FP), CX
	MOVQ accumulator+24(FP), DX
	MOVQ scalar+32(FP), SI
	VMOVDQU64 (BX), X0
	VMOVDQU64 (CX), X1
	VMOVDQU64 (DX), X2
	VPMADD52LUQ X0, X1, X2
	VMOVDQU64 X2, 0(AX)
	VMOVDQU64 (DX), X3
	VPMADD52HUQ X0, X1, X3
	VMOVDQU64 X3, 16(AX)
	KMOVQ mask+40(FP), K1
	VMOVDQU64 (DX), X4
	VPMADD52LUQ X0, X1, K1, X4
	VMOVDQU64 X4, 32(AX)
	VMOVDQU64 (DX), X5
	VPMADD52LUQ.Z X0, X1, K1, X5
	VMOVDQU64 X5, 48(AX)
	VMOVDQU64 (DX), X6
	VPMADD52LUQ.BCST (SI), X1, X6
	VMOVDQU64 X6, 64(AX)
	RET
`
	requireX86GoAssemblerResult(t, "amd64", source, true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	frame := FrameLayout{Params: []FrameSlot{
		{Offset: 0, Type: Ptr, Index: 0, Field: -1},
		{Offset: 8, Type: Ptr, Index: 1, Field: -1},
		{Offset: 16, Type: Ptr, Index: 2, Field: -1},
		{Offset: 24, Type: Ptr, Index: 3, Field: -1},
		{Offset: 32, Type: Ptr, Index: 4, Field: -1},
		{Offset: 40, Type: I64, Index: 5, Field: -1},
	}}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var runPrefix []string
	if crossRosetta {
		triple = "x86_64-apple-macosx"
		runPrefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	ir, err := Translate(file, Options{
		Goarch:       "amd64",
		TargetTriple: triple,
		Sigs: map[string]FuncSig{
			"ifmaSemantics": {
				Name:  "ifmaSemantics",
				Args:  []LLVMType{Ptr, Ptr, Ptr, Ptr, Ptr, I64},
				Ret:   Void,
				Frame: frame,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void ifmaSemantics(uint64_t *, const uint64_t *, const uint64_t *, const uint64_t *, const uint64_t *, uint64_t);
static const uint64_t mask52 = (((uint64_t)1) << 52) - 1;
static uint64_t lo(uint64_t a, uint64_t b) {
  return (uint64_t)((((unsigned __int128)(a & mask52)) * (b & mask52)) & mask52);
}
static uint64_t hi(uint64_t a, uint64_t b) {
  return (uint64_t)((((unsigned __int128)(a & mask52)) * (b & mask52)) >> 52);
}
int main(void) {
  const uint64_t first[2] = {(UINT64_C(1) << 60) | mask52, (UINT64_C(1) << 55) | (UINT64_C(1) << 51) | 3};
  const uint64_t second[2] = {(UINT64_C(1) << 59) | mask52, (UINT64_C(1) << 58) | (UINT64_C(1) << 51) | 5};
  const uint64_t accumulator[2] = {UINT64_MAX - 15, 100};
  const uint64_t scalar = (UINT64_C(1) << 63) | 7;
  uint64_t out[10] = {0};
  const uint64_t want[10] = {
    accumulator[0] + lo(first[0], second[0]), accumulator[1] + lo(first[1], second[1]),
    accumulator[0] + hi(first[0], second[0]), accumulator[1] + hi(first[1], second[1]),
    accumulator[0] + lo(first[0], second[0]), accumulator[1],
    accumulator[0] + lo(first[0], second[0]), 0,
    accumulator[0] + lo(scalar, second[0]), accumulator[1] + lo(scalar, second[1]),
  };
  ifmaSemantics(out, first, second, accumulator, &scalar, 1);
  for (int i = 0; i < 10; i++) if (out[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "ifma", triple, ir, mainC, runPrefix)
}
