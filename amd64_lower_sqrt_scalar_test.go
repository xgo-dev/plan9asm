package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateX86ScalarSqrtCompleteGo127Forms(t *testing.T) {
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
			source.WriteString("TEXT scalarsqrtforms(SB),$0-0\n")
			for _, op := range []string{"VSQRTSS", "VSQRTSD"} {
				fmt.Fprintf(&source, "\t%s X0, X1, X2\n", op)
				fmt.Fprintf(&source, "\t%s 8(BX), X3, X4\n", op)
				fmt.Fprintf(&source, "\t%s X29, X30, X31\n", op)
				if target.goarch == "amd64" {
					fmt.Fprintf(&source, "\t%s X5, X6, K1, X7\n", op)
					fmt.Fprintf(&source, "\t%s.Z 16(BX), X8, K2, X9\n", op)
				}
				for _, rounding := range []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"} {
					fmt.Fprintf(&source, "\t%s.%s X10, X11, X12\n", op, rounding)
					if target.goarch == "amd64" {
						fmt.Fprintf(&source, "\t%s.%s.Z X13, X14, K3, X15\n", op, rounding)
					}
				}
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
					"scalarsqrtforms": {Name: "scalarsqrtforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "scalar-sqrt-"+target.name+".ll", "scalar-sqrt-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86ScalarSqrtRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"VSQRTSS X0, X1",
		"VSQRTSD X0, X1, X2, X3, X4",
		"VSQRTSS Y0, X1, X2",
		"VSQRTSD X0, Y1, X2",
		"VSQRTSS X0, X1, K0, X2",
		"VSQRTSD.Z X0, X1, X2",
		"VSQRTSS.BCST 8(BX), X1, X2",
		"VSQRTSD.SAE X0, X1, X2",
		"VSQRTSS.RN_SAE 8(BX), X1, X2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			requireX86GoAssemblerResult(t, "amd64", "TEXT bad(SB),$0-0\n\t"+instruction+"\n\tRET\n", false)
			assertX86ScalarSqrtRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	assertX86ScalarSqrtRejected(t, "386", "i386-unknown-linux-gnu", "VSQRTSS X0, X1, K1, X2")
}

func assertX86ScalarSqrtRejected(t *testing.T, goarch, triple, instruction string) {
	t.Helper()
	file, err := Parse(ArchAMD64, "TEXT bad(SB),$0-0\n\t"+instruction+"\n\tRET\n")
	if err != nil {
		return
	}
	if _, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       goarch,
		Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
	}); err == nil {
		t.Fatalf("Translate accepted %q outside Go 1.27's VSQRTSS/VSQRTSD _yvaddsd forms for %s", instruction, goarch)
	}
}

func TestAMD64ScalarSqrtRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test only runs on amd64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	source := `
TEXT scalarsqrt(SB),NOSPLIT,$0-64
	MOVQ out+0(FP), AX
	MOVQ source64+8(FP), BX
	MOVQ passthrough64+16(FP), CX
	MOVQ source32+24(FP), DX
	MOVQ passthrough32+32(FP), SI
	MOVQ old64+40(FP), DI
	MOVQ old32+48(FP), R8
	MOVQ mask+56(FP), R9
	KMOVQ R9, K1

	VMOVUPD (BX), X0
	VMOVUPD (CX), X1
	VSQRTSD.RD_SAE X0, X1, X2
	VMOVUPD X2, 0(AX)

	VMOVUPS (DX), X0
	VMOVUPS (SI), X1
	VSQRTSS.RU_SAE X0, X1, X2
	VMOVUPS X2, 16(AX)

	VMOVUPD (BX), X0
	VMOVUPD (CX), X1
	VMOVUPD (DI), X4
	VSQRTSD X0, X1, K1, X4
	VMOVUPD X4, 32(AX)

	VMOVUPS (DX), X0
	VMOVUPS (SI), X1
	VMOVUPS (R8), X4
	VSQRTSS.Z X0, X1, K1, X4
	VMOVUPS X4, 48(AX)
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
		{Offset: 24, Type: Ptr, Index: 3, Field: -1},
		{Offset: 32, Type: Ptr, Index: 4, Field: -1},
		{Offset: 40, Type: Ptr, Index: 5, Field: -1},
		{Offset: 48, Type: Ptr, Index: 6, Field: -1},
		{Offset: 56, Type: I64, Index: 7, Field: -1},
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
			"scalarsqrt": {Name: "scalarsqrt", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, I64}, Ret: Void, Frame: frame},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mainC := `
#include <stdint.h>
extern void scalarsqrt(uint8_t *, const double *, const double *, const float *, const float *, const double *, const float *, uint64_t);
int main(void) {
  const double source64[2] = {9.0, 77.0};
  const double passthrough64[2] = {100.0, 101.0};
  const float source32[4] = {16.0f, 17.0f, 18.0f, 19.0f};
  const float passthrough32[4] = {200.0f, 201.0f, 202.0f, 203.0f};
  const double old64[2] = {300.0, 301.0};
  const float old32[4] = {400.0f, 401.0f, 402.0f, 403.0f};
  union { uint8_t bytes[64]; double d64[8]; float f32[16]; } out = {0};
  scalarsqrt(out.bytes, source64, passthrough64, source32, passthrough32, old64, old32, 0);
  if (out.d64[0] != 3.0 || out.d64[1] != 101.0) return 1;
  if (out.f32[4] != 4.0f || out.f32[5] != 201.0f || out.f32[6] != 202.0f || out.f32[7] != 203.0f) return 2;
  if (out.d64[4] != 300.0 || out.d64[5] != 101.0) return 3;
  if (out.f32[12] != 0.0f || out.f32[13] != 201.0f || out.f32[14] != 202.0f || out.f32[15] != 203.0f) return 4;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "scalar_sqrt", triple, ll, mainC, runPrefix)
}
