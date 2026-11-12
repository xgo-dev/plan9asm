package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

const arm64RawMLAForms = `
TEXT rawmlaforms(SB),$0-0
	WORD $0x0e229420 // MLA V0.8B, V1.8B, V2.8B
	WORD $0x4e259483 // MLA V3.16B, V4.16B, V5.16B
	WORD $0x0e6894e6 // MLA V6.4H, V7.4H, V8.4H
	WORD $0x4e6b9549 // MLA V9.8H, V10.8H, V11.8H
	WORD $0x0eae95ac // MLA V12.2S, V13.2S, V14.2S
	WORD $0x4eb1960f // MLA V15.4S, V16.4S, V17.4S
	WORD $0x2f740a72 // MLA V18.4H, V19.4H, V4.H[7]
	WORD $0x6f750ab4 // MLA V20.8H, V21.8H, V5.H[7]
	WORD $0x2fb80af6 // MLA V22.2S, V23.2S, V24.S[3]
	WORD $0x6fbb0b59 // MLA V25.4S, V26.4S, V27.S[3]
	RET
`

func TestTranslateARM64RawMLACompleteAdvancedSIMDFormats(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64RawMLAForms, true)
	file, err := Parse(ArchARM64, arm64RawMLAForms)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"rawmlaforms": {Name: "rawmlaforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"mul <8 x i8>", "mul <16 x i8>",
				"mul <4 x i16>", "mul <8 x i16>",
				"mul <2 x i32>", "mul <4 x i32>",
				"add <8 x i8>", "add <4 x i32>",
				"extractelement <8 x i16>", "extractelement <4 x i32>",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 raw MLA lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-mla.ll", "arm64-raw-mla.o", ll)
		})
	}
}

func TestARM64RawMLARuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawmla(SB),$0-24
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	MOVD inout+16(FP), R2
	VLD1 (R0), [V8.H8]
	VLD1 (R1), [V7.H8]
	VLD1 (R2), [V2.H8]
	WORD $0x4e679502 // MLA V2.8H, V8.8H, V7.8H
	VST1 [V2.H8], (R2)
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
			"rawmla": {
				Name: "rawmla", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void rawmla(const uint16_t *, const uint16_t *, uint16_t *);
int main(void) {
  const uint16_t a[8] = {0,1,65535,32768,2,3,4,5};
  const uint16_t b[8] = {7,65535,3,2,9,10,11,12};
	const uint16_t initial[8] = {9,9,9,9,65000,65000,65000,65000};
	uint16_t got[8];
	for (int i = 0; i < 8; i++) got[i] = initial[i];
  rawmla(a, b, got);
  for (int i = 0; i < 8; i++) {
	uint16_t want = (uint16_t)(initial[i] + (uint16_t)(a[i] * b[i]));
	if (got[i] != want) return i + 1;
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_mla", triple, ll, mainC, nil)
}

func TestARM64RawMLADecoderRejectsAdjacentMLSEncoding(t *testing.T) {
	if _, ok := decodeARM64RawMLA(0x2e229420); ok {
		t.Fatal("MLA decoder accepted adjacent MLS encoding")
	}
}
