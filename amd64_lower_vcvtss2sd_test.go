package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateAMD64VCVTSS2SDCompleteGo127Forms(t *testing.T) {
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
			source.WriteString("TEXT vcvtss2sdforms(SB),$0-0\n")
			for _, op := range []string{"VCVTSS2SD", "VCVTSD2SS"} {
				fmt.Fprintf(&source, "\t%s X0, X1, X2\n", op)
				fmt.Fprintf(&source, "\t%s (AX), X3, X4\n", op)
				fmt.Fprintf(&source, "\t%s X31, X30, X29\n", op)
				if op == "VCVTSS2SD" {
					fmt.Fprintf(&source, "\t%s.SAE X31, X30, X29\n", op)
				} else {
					for _, rounding := range []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"} {
						fmt.Fprintf(&source, "\t%s.%s X31, X30, X29\n", op, rounding)
					}
				}
				if target.goarch == "amd64" {
					fmt.Fprintf(&source, "\t%s X31, X30, K1, X29\n", op)
					fmt.Fprintf(&source, "\t%s.Z (AX), X30, K2, X29\n", op)
					if op == "VCVTSS2SD" {
						fmt.Fprintf(&source, "\t%s.SAE.Z X31, X30, K3, X29\n", op)
					} else {
						fmt.Fprintf(&source, "\t%s.RD_SAE.Z X31, X30, K3, X29\n", op)
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
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"vcvtss2sdforms": {Name: "vcvtss2sdforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "vcvtss2sd-"+target.name+".ll", "vcvtss2sd-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86ScalarPrecisionConvertRejectsFormsOutsideGo127(t *testing.T) {
	tests := []struct {
		goarch      string
		triple      string
		instruction string
	}{
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "VCVTSS2SD.RD_SAE X0, X1, X2"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "VCVTSD2SS.SAE X0, X1, X2"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "VCVTSS2SD.SAE (AX), X1, X2"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "VCVTSD2SS.RN_SAE (AX), X1, X2"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "VCVTSS2SD.Z X0, X1, X2"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "VCVTSD2SS X0, X1, K0, X2"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "VCVTSS2SD Y0, X1, X2"},
		{goarch: "386", triple: "i386-unknown-linux-gnu", instruction: "VCVTSD2SS X0, X1, K1, X2"},
	}
	for _, test := range tests {
		t.Run(test.goarch+"_"+strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(test.instruction), func(t *testing.T) {
			source := "TEXT bad(SB),NOSPLIT,$0-0\n\t" + test.instruction + "\n\tRET\n"
			requireX86GoAssemblerResult(t, test.goarch, source, false)
			file, err := Parse(ArchAMD64, source)
			if err == nil {
				_, err = Translate(file, Options{
					TargetTriple: test.triple,
					Goarch:       test.goarch,
					Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
				})
			}
			if err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's scalar precision-conversion forms for %s", test.instruction, test.goarch)
			}
		})
	}
}

func TestAMD64ScalarPrecisionConvertRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test only runs on amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT scalarPrecisionConvertSemantics(SB),NOSPLIT,$0-48
	MOVQ out+0(FP), AX
	MOVQ doubles+8(FP), BX
	MOVQ floats+16(FP), CX
	MOVQ upper+24(FP), DX
	MOVQ old+32(FP), SI
	KMOVQ mask+40(FP), K1
	MOVSD (BX), X0
	MOVUPS (DX), X1
	MOVUPS (SI), X2
	VCVTSD2SS.RN_SAE X0, X1, X2
	MOVUPS X2, 0(AX)
	VCVTSD2SS.RD_SAE X0, X1, X2
	MOVUPS X2, 16(AX)
	VCVTSD2SS.RU_SAE X0, X1, X2
	MOVUPS X2, 32(AX)
	VCVTSD2SS.RZ_SAE X0, X1, X2
	MOVUPS X2, 48(AX)
	MOVUPS (SI), X2
	VCVTSD2SS.RU_SAE X0, X1, K1, X2
	MOVUPS X2, 64(AX)
	MOVUPS (SI), X2
	VCVTSD2SS.RU_SAE.Z X0, X1, K1, X2
	MOVUPS X2, 80(AX)
	MOVSS (CX), X0
	VCVTSS2SD.SAE X0, X1, X2
	MOVUPS X2, 96(AX)
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
		{Offset: 40, Type: I64, Index: 5, Field: -1},
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
			"scalarPrecisionConvertSemantics": {Name: "scalarPrecisionConvertSemantics", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr, Ptr, I64}, Ret: Void, Frame: frame},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <string.h>
extern void scalarPrecisionConvertSemantics(uint32_t *, const double *, const float *, const uint32_t *, const uint32_t *, uint64_t);
int main(void) {
  double input = 1.0 + 0x1p-24;
  float input32 = 1.5f;
  uint32_t upper[4] = {0xaaaaaaaaU, 0x11111111U, 0x22222222U, 0x33333333U};
  uint32_t old[4] = {0xdeadbeefU, 0xbbbbbbbbU, 0xccccccccU, 0xddddddddU};
  uint32_t out[28] = {0};
  scalarPrecisionConvertSemantics(out, &input, &input32, upper, old, 0);
  uint32_t low[4] = {0x3f800000U, 0x3f800000U, 0x3f800001U, 0x3f800000U};
  for (int group = 0; group < 4; group++) {
    if (out[group*4] != low[group]) return 1 + group;
    for (int lane = 1; lane < 4; lane++) if (out[group*4+lane] != upper[lane]) return 10 + group*4 + lane;
  }
  if (out[16] != old[0]) return 40;
  if (out[20] != 0) return 41;
  for (int lane = 1; lane < 4; lane++) {
    if (out[16+lane] != upper[lane]) return 42 + lane;
    if (out[20+lane] != upper[lane]) return 46 + lane;
  }
  uint64_t converted = 0, want = 0x3ff8000000000000ULL;
  memcpy(&converted, &out[24], sizeof(converted));
  if (converted != want) return 60;
  if (out[26] != upper[2] || out[27] != upper[3]) return 61;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "scalar_precision_convert", triple, ll, mainC, runPrefix)
}
