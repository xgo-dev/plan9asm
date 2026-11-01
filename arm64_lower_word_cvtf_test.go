package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

const arm64RawCVTFForms = `
TEXT rawcvtfforms(SB),$0-0
	WORD $0x0e21d820 // SCVTF V0.2S, V1.2S
	WORD $0x4e21d862 // SCVTF V2.4S, V3.4S
	WORD $0x4e61d8a4 // SCVTF V4.2D, V5.2D
	WORD $0x2e21d8e6 // UCVTF V6.2S, V7.2S
	WORD $0x6e21d928 // UCVTF V8.4S, V9.4S
	WORD $0x6e61d96a // UCVTF V10.2D, V11.2D
	RET
`

func TestTranslateARM64RawCVTFCompleteAdvancedSIMDFormats(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64RawCVTFForms, true)
	file, err := Parse(ArchARM64, arm64RawCVTFForms)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"rawcvtfforms": {Name: "rawcvtfforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"sitofp <2 x i32>", "sitofp <4 x i32>", "sitofp <2 x i64>", "uitofp <2 x i32>", "uitofp <4 x i32>", "uitofp <2 x i64>"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 raw SCVTF/UCVTF lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-cvtf.ll", "arm64-raw-cvtf.o", ll)
		})
	}
}

func TestARM64RawCVTFRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawcvtf(SB),$0-16
	MOVD in+0(FP), R0
	MOVD out+8(FP), R1
	VLD1 (R0), [V0.S4]
	WORD $0x4e21d801 // SCVTF V1.4S, V0.4S
	WORD $0x6e21d802 // UCVTF V2.4S, V0.4S
	VST1 [V1.S4, V2.S4], (R1)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ll, err := Translate(file, Options{
		TargetTriple: triple, Goarch: "arm64",
		Sigs: map[string]FuncSig{
			"rawcvtf": {
				Name: "rawcvtf", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <limits.h>
extern void rawcvtf(const uint32_t *, float *);
int main(void) {
  const uint32_t input[4] = {UINT32_MAX, 0x80000000u, 0u, INT32_MAX};
  float got[8] = {0};
  rawcvtf(input, got);
  for (int i = 0; i < 4; i++) {
    if (got[i] != (float)(int32_t)input[i]) return i + 1;
    if (got[4+i] != (float)input[i]) return i + 11;
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_cvtf", triple, ll, mainC, nil)
}

func TestARM64RawCVTFDecoderRejectsAdjacentAndReservedEncodings(t *testing.T) {
	for _, word := range []uint32{0x4ea1b9ac, 0x0e61d800} { // FCVTZS and reserved D1.
		if _, ok := decodeARM64RawCVTF(word); ok {
			t.Fatalf("SCVTF/UCVTF decoder accepted adjacent/reserved encoding %#08x", word)
		}
	}
}
