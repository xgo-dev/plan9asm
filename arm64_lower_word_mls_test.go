package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

const arm64RawMLSForms = `
TEXT rawmlsforms(SB),$0-0
	WORD $0x2e229420 // MLS V0.8B, V1.8B, V2.8B
	WORD $0x6e259483 // MLS V3.16B, V4.16B, V5.16B
	WORD $0x2e6894e6 // MLS V6.4H, V7.4H, V8.4H
	WORD $0x6e6b9549 // MLS V9.8H, V10.8H, V11.8H
	WORD $0x2eae95ac // MLS V12.2S, V13.2S, V14.2S
	WORD $0x6eb1960f // MLS V15.4S, V16.4S, V17.4S
	WORD $0x2f744a72 // MLS V18.4H, V19.4H, V4.H[7]
	WORD $0x6f754ab4 // MLS V20.8H, V21.8H, V5.H[7]
	WORD $0x2fb84af6 // MLS V22.2S, V23.2S, V24.S[3]
	WORD $0x6fbb4b59 // MLS V25.4S, V26.4S, V27.S[3]
	RET
`

func TestTranslateARM64RawMLSCompleteAdvancedSIMDFormats(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64RawMLSForms, true)
	file, err := Parse(ArchARM64, arm64RawMLSForms)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"rawmlsforms": {Name: "rawmlsforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"mul <8 x i8>", "mul <16 x i8>",
				"mul <4 x i16>", "mul <8 x i16>",
				"mul <2 x i32>", "mul <4 x i32>",
				"sub <8 x i8>", "sub <4 x i32>",
				"extractelement <8 x i16>", "extractelement <4 x i32>",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 raw MLS lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-mls.ll", "arm64-raw-mls.o", ll)
		})
	}
}

func TestARM64RawMLSRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawmls(SB),$0-24
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	MOVD inout+16(FP), R2
	VLD1 (R0), [V0.S4]
	VLD1 (R1), [V1.S4]
	VLD1 (R2), [V2.S4]
	WORD $0x6ea19402 // MLS V2.4S, V0.4S, V1.4S
	VST1 [V2.S4], (R2)
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
			"rawmls": {
				Name: "rawmls", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
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
extern void rawmls(const uint32_t *, const uint32_t *, uint32_t *);
int main(void) {
  const uint32_t a[4] = {0, 1, 0xffffffffu, 0x80000000u};
  const uint32_t b[4] = {7, 0xffffffffu, 3, 2};
  uint32_t got[4] = {9, 9, 9, 9};
  const uint32_t want[4] = {9, 10, 12, 9};
  rawmls(a, b, got);
  for (int i = 0; i < 4; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_mls", triple, ll, mainC, nil)
}

func TestARM64RawMLSDecoderRejectsAdjacentMLAEncoding(t *testing.T) {
	if _, ok := decodeARM64RawMLS(0x0e229420); ok {
		t.Fatal("MLS decoder accepted adjacent MLA encoding")
	}
}
