package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

type x86ScalarIntegerFloatTestSpec struct {
	op       string
	rounding bool
}

func go127X86ScalarIntegerFloatSpecs() []x86ScalarIntegerFloatTestSpec {
	return []x86ScalarIntegerFloatTestSpec{
		{op: "VCVTSI2SDL"},
		{op: "VCVTSI2SDQ", rounding: true},
		{op: "VCVTSI2SSL", rounding: true},
		{op: "VCVTSI2SSQ", rounding: true},
		{op: "VCVTUSI2SDL"},
		{op: "VCVTUSI2SDQ", rounding: true},
		{op: "VCVTUSI2SSL", rounding: true},
		{op: "VCVTUSI2SSQ", rounding: true},
	}
}

func TestTranslateX86ScalarIntegerFloatCompleteGo127Forms(t *testing.T) {
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
			source.WriteString("TEXT scalarintegerfloatforms(SB),$0-0\n")
			for _, spec := range go127X86ScalarIntegerFloatSpecs() {
				fmt.Fprintf(&source, "\t%s AX, X0, X1\n", spec.op)
				fmt.Fprintf(&source, "\t%s 8(BX), X2, X3\n", spec.op)
				fmt.Fprintf(&source, "\t%s CX, X29, X30\n", spec.op)
				if spec.rounding {
					for _, rounding := range []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"} {
						fmt.Fprintf(&source, "\t%s.%s DX, X30, X31\n", spec.op, rounding)
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
					"scalarintegerfloatforms": {Name: "scalarintegerfloatforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "scalar-integer-float-"+target.name+".ll", "scalar-integer-float-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86ScalarIntegerFloatRejectsFormsOutsideGo127Tables(t *testing.T) {
	for _, instruction := range []string{
		"VCVTSI2SDL AX, X1",
		"VCVTSI2SDQ AX, X0, X1, X2",
		"VCVTSI2SSL $1, X0, X1",
		"VCVTSI2SSQ X0, X1, X2",
		"VCVTUSI2SDL AX, Y0, X1",
		"VCVTUSI2SDQ AX, X0, Y1",
		"VCVTUSI2SSL AX, X0, K1, X1",
		"VCVTUSI2SSQ.Z AX, X0, X1",
		"VCVTSI2SDL.RN_SAE AX, X0, X1",
		"VCVTUSI2SDL.RD_SAE AX, X0, X1",
		"VCVTSI2SDQ.SAE AX, X0, X1",
		"VCVTUSI2SSQ.BCST 8(BX), X0, X1",
		"VCVTSI2SSL.RN_SAE 8(BX), X0, X1",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			requireX86GoAssemblerResult(t, "amd64", "TEXT bad(SB),$0-0\n\t"+instruction+"\n\tRET\n", false)
			assertX86ScalarIntegerFloatRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	requireX86GoAssemblerResult(t, "386", "TEXT bad(SB),$0-0\n\tVCVTSI2SDQ R8, X0, X1\n\tRET\n", false)
	assertX86ScalarIntegerFloatRejected(t, "386", "i386-unknown-linux-gnu", "VCVTSI2SDQ R8, X0, X1")
}

func assertX86ScalarIntegerFloatRejected(t *testing.T, goarch, triple, instruction string) {
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
		t.Fatalf("Translate accepted %q outside Go 1.27's scalar integer-to-float tables for %s", instruction, goarch)
	}
}

func TestAMD64ScalarIntegerFloatRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test only runs on amd64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	source := `
TEXT scalarintegerfloat(SB),NOSPLIT,$0-56
	MOVQ out+0(FP), AX
	MOVQ signed32+8(FP), BX
	MOVQ signed64+16(FP), CX
	MOVQ unsigned32+24(FP), DX
	MOVQ unsigned64+32(FP), SI
	MOVQ passthrough32+40(FP), DI
	MOVQ passthrough64+48(FP), R8
	MOVQ (CX), R9
	MOVL (BX), R10
	MOVQ (SI), R11
	MOVL (DX), R12

	VMOVUPD (R8), X0
	VCVTSI2SDL (BX), X0, X1
	VMOVUPD X1, 0(AX)
	VCVTSI2SDQ.RN_SAE R9, X0, X1
	VMOVUPD X1, 16(AX)

	VMOVUPS (DI), X0
	VCVTSI2SSL.RD_SAE R10, X0, X1
	VMOVUPS X1, 32(AX)
	VCVTSI2SSQ.RU_SAE R9, X0, X1
	VMOVUPS X1, 48(AX)

	VMOVUPD (R8), X0
	VCVTUSI2SDL (DX), X0, X1
	VMOVUPD X1, 64(AX)
	VCVTUSI2SDQ.RZ_SAE R11, X0, X1
	VMOVUPD X1, 80(AX)

	VMOVUPS (DI), X0
	VCVTUSI2SSL.RD_SAE R12, X0, X1
	VMOVUPS X1, 96(AX)
	VCVTUSI2SSQ.RN_SAE R11, X0, X1
	VMOVUPS X1, 112(AX)
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
			"scalarintegerfloat": {Name: "scalarintegerfloat", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, Ptr}, Ret: Void, Frame: frame},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mainC := `
#include <stdint.h>
#include <stdio.h>
extern void scalarintegerfloat(uint8_t *, const int32_t *, const int64_t *, const uint32_t *, const uint64_t *, const float *, const double *);
int main(void) {
  const int32_t signed32 = -16777217;
  const int64_t signed64 = -16777217;
  const uint32_t unsigned32 = UINT32_MAX;
  const uint64_t unsigned64 = UINT64_MAX;
  const float passthrough32[4] = {200.0f, 201.0f, 202.0f, 203.0f};
  const double passthrough64[2] = {100.0, 101.0};
  union { uint8_t bytes[128]; double d64[16]; float f32[32]; } out = {0};
  scalarintegerfloat(out.bytes, &signed32, &signed64, &unsigned32, &unsigned64, passthrough32, passthrough64);
  if (out.d64[0] != -16777217.0 || out.d64[1] != 101.0) return 1;
  if (out.d64[2] != -16777217.0 || out.d64[3] != 101.0) return 2;
  if (out.f32[8] != -16777218.0f || out.f32[9] != 201.0f || out.f32[10] != 202.0f || out.f32[11] != 203.0f) return 3;
  if (out.f32[12] != -16777216.0f || out.f32[13] != 201.0f || out.f32[14] != 202.0f || out.f32[15] != 203.0f) return 4;
  if (out.d64[8] != 4294967295.0 || out.d64[9] != 101.0) return 5;
  if (out.d64[10] != 18446744073709549568.0 || out.d64[11] != 101.0) return 6;
  if (out.f32[24] != 4294967040.0f || out.f32[25] != 201.0f || out.f32[26] != 202.0f || out.f32[27] != 203.0f) {
    fprintf(stderr, "unsigned32 RD result=%a upper={%a,%a,%a}\n", out.f32[24], out.f32[25], out.f32[26], out.f32[27]);
    return 7;
  }
  if (out.f32[28] != 18446744073709551616.0f || out.f32[29] != 201.0f || out.f32[30] != 202.0f || out.f32[31] != 203.0f) return 8;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "scalar_integer_float", triple, ll, mainC, runPrefix)
}
