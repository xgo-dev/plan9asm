package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateAMD64VectorAlignCompleteGo127Forms(t *testing.T) {
	// VALIGND/Q share Go 1.27's six-row _yvalignd table: X/Y/Z,
	// each with an unmasked and K1-K7 masked row. Their EVEX attributes add
	// D/Q scalar broadcast and zeroing.
	var source strings.Builder
	source.WriteString("TEXT vector_align_forms(SB),$0-0\n")
	for _, op := range []string{"VALIGND", "VALIGNQ"} {
		for _, width := range []string{"X", "Y", "Z"} {
			fmt.Fprintf(&source, "\t%s $0, %s0, %s1, %s2\n", op, width, width, width)
			fmt.Fprintf(&source, "\t%s $255, 8(BX), %s3, %s4\n", op, width, width)
			fmt.Fprintf(&source, "\t%s $1, %s5, %s6, K1, %s7\n", op, width, width, width)
			fmt.Fprintf(&source, "\t%s.Z $2, 16(BX), %s8, K2, %s9\n", op, width, width)
			fmt.Fprintf(&source, "\t%s.BCST $3, 24(BX), %s10, %s11\n", op, width, width)
			fmt.Fprintf(&source, "\t%s.BCST.Z $4, 32(BX), %s12, K3, %s13\n", op, width, width)
		}
		fmt.Fprintf(&source, "\t%s $5, X29, X30, X31\n", op)
		fmt.Fprintf(&source, "\t%s $6, Y29, Y30, Y31\n", op)
		fmt.Fprintf(&source, "\t%s $7, Z29, Z30, Z31\n", op)
	}
	source.WriteString("\tRET\n")

	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		triple string
	}{
		{name: "darwin-amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", triple: "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			ir, err := Translate(file, Options{
				Goarch:       "amd64",
				TargetTriple: target.triple,
				Sigs: map[string]FuncSig{
					"vector_align_forms": {Name: "vector_align_forms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "vector-align-"+target.name+".ll", "vector-align-"+target.name+".o", ir)
		})
	}
}

func TestTranslateAMD64VectorAlignRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"VALIGND X0, X1, X2",
		"VALIGND $0, X0, X1",
		"VALIGNQ $0, X0, X1, X2, X3, X4",
		"VALIGND $-1, X0, X1, X2",
		"VALIGNQ $256, X0, X1, X2",
		"VALIGND AX, X0, X1, X2",
		"VALIGND $0, Y0, X1, X2",
		"VALIGNQ $0, X0, Y1, X2",
		"VALIGND $0, X0, X1, Y2",
		"VALIGNQ $0, X0, 8(BX), X2",
		"VALIGND $0, X0, X1, 8(BX)",
		"VALIGND $0, X0, X1, K0, X2",
		"VALIGNQ $0, X0, X1, K8, X2",
		"VALIGND.Z $0, X0, X1, X2",
		"VALIGNQ.BCST $0, X0, X1, X2",
		"VALIGND.BCST.Z $0, 8(BX), X1, X2",
		"VALIGNQ.Z.BCST $0, 8(BX), X1, K1, X2",
		"VALIGND.SAE $0, X0, X1, X2",
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
				t.Fatalf("Translate accepted %q outside Go 1.27's VALIGND/Q table", instruction)
			}
		})
	}
}

func TestTranslate386VectorAlignMatchesGoAssemblerOperandLimit(t *testing.T) {
	for _, instruction := range []string{
		"VALIGND $0, X0, X1, X2",
		"VALIGNQ $255, 8(BX), Y1, Y2",
		"VALIGND.Z $1, Z0, Z1, K1, Z2",
		"VALIGNQ.BCST.Z $2, 16(BX), X1, K7, X2",
	} {
		t.Run(strings.NewReplacer(" ", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireX86GoAssemblerResult(t, "386", source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				return
			}
			for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
				if _, err := Translate(file, Options{
					Goarch:       "386",
					TargetTriple: triple,
					Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
				}); err == nil {
					t.Fatalf("Translate accepted 386 %q although Go 1.27 rejects its operand count", instruction)
				}
			}
		})
	}
}

func TestAMD64VectorAlignRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test only runs on amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT vectorAlignSemantics(SB),NOSPLIT,$0-40
	MOVQ out+0(FP), AX
	MOVQ first+8(FP), BX
	MOVQ second+16(FP), CX
	MOVQ scalar+24(FP), DX
	VMOVDQU32 (BX), X0
	VMOVDQU32 (CX), X1
	VALIGND $1, X0, X1, X2
	VMOVDQU32 X2, 0(AX)
	VALIGND $255, X0, X1, X3
	VMOVDQU32 X3, 16(AX)
	VALIGNQ $1, X0, X1, X4
	VMOVDQU32 X4, 32(AX)
	KMOVQ mask+32(FP), K1
	VMOVDQU32 X0, X5
	VALIGND $1, X0, X1, K1, X5
	VMOVDQU32 X5, 48(AX)
	VALIGND.Z $1, X0, X1, K1, X6
	VMOVDQU32 X6, 64(AX)
	VALIGND.BCST $1, (DX), X1, X7
	VMOVDQU32 X7, 80(AX)
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
		{Offset: 24, Type: Ptr, Index: 3, Field: -1},
		{Offset: 32, Type: I64, Index: 4, Field: -1},
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
			"vectorAlignSemantics": {
				Name:  "vectorAlignSemantics",
				Args:  []LLVMType{Ptr, Ptr, Ptr, Ptr, I64},
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
extern void vectorAlignSemantics(uint32_t *, const uint32_t *, const uint32_t *, const uint32_t *, uint64_t);
int main(void) {
  uint32_t first[4] = {10, 11, 12, 13};
  uint32_t second[4] = {20, 21, 22, 23};
  uint32_t scalar = 99;
  uint32_t out[24] = {0};
  const uint32_t want[24] = {
    11, 12, 13, 20,
    13, 20, 21, 22,
    12, 13, 20, 21,
    11, 11, 13, 13,
    11, 0, 13, 0,
    99, 99, 99, 20,
  };
  vectorAlignSemantics(out, first, second, &scalar, 5);
  for (int i = 0; i < 24; i++) if (out[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "vector_align", triple, ir, mainC, runPrefix)
}
