package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

const arm64RawFloatAbsNegForms = `
TEXT rawfloatabsnegforms(SB),$0-0
	WORD $0x0ef8f820 // FABS V0.4H, V1.4H
	WORD $0x4ef8f820 // FABS V0.8H, V1.8H
	WORD $0x0ea0f820 // FABS V0.2S, V1.2S
	WORD $0x4ea0f820 // FABS V0.4S, V1.4S
	WORD $0x4ee0f820 // FABS V0.2D, V1.2D
	WORD $0x2ef8f820 // FNEG V0.4H, V1.4H
	WORD $0x6ef8f820 // FNEG V0.8H, V1.8H
	WORD $0x2ea0f820 // FNEG V0.2S, V1.2S
	WORD $0x6ea0f820 // FNEG V0.4S, V1.4S
	WORD $0x6ee0f820 // FNEG V0.2D, V1.2D
	RET
`

func TestTranslateARM64RawFloatAbsNegCompleteAdvancedSIMDFormats(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64RawFloatAbsNegForms, true)
	file, err := Parse(ArchARM64, arm64RawFloatAbsNegForms)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"rawfloatabsnegforms": {Name: "rawfloatabsnegforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"@llvm.fabs.v4f16", "@llvm.fabs.v8f16", "fneg <4 x half>", "fneg <8 x half>", "@llvm.fabs.v2f32", "@llvm.fabs.v4f32", "@llvm.fabs.v2f64", "fneg <2 x float>", "fneg <4 x float>", "fneg <2 x double>"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("raw float abs/neg for %s omitted %s:\n%s", triple, want, ir)
				}
			}
			compileLLVMToObject(t, llc, triple, "raw-float-abs-neg.ll", "raw-float-abs-neg.o", ir)
		})
	}
}

func TestARM64RawFloatAbsNegRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawfloatabsneg(SB),$0-16
	MOVD input+0(FP), R0
	MOVD output+8(FP), R1
	VLD1 (R0), [V0.H8]
	WORD $0x4ef8f801 // FABS V1.8H, V0.8H
	WORD $0x6ef8f802 // FNEG V2.8H, V0.8H
	VST1.P [V1.H8], 16(R1)
	VST1 [V2.H8], (R1)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir, err := Translate(file, Options{
		TargetTriple: triple, Goarch: "arm64",
		Sigs: map[string]FuncSig{"rawfloatabsneg": {
			Name: "rawfloatabsneg", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void rawfloatabsneg(const uint16_t *, uint16_t *);
int main(void) {
  const uint16_t input[8] = {0xbc00,0x4000,0xc200,0x4400,0xc500,0x4600,0xc700,0x4800};
  uint16_t got[16] = {0};
  rawfloatabsneg(input, got);
  for (int i = 0; i < 8; i++) {
    if (got[i] != (input[i] & 0x7fff)) return i + 1;
    if (got[8+i] != (input[i] ^ 0x8000)) return i + 9;
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_float_abs_neg", triple, ir, mainC, nil)
}
