package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

const arm64RawUMULLForms = `
TEXT rawumullforms(SB),$0-0
	WORD $0x2e22c020 // UMULL V0.8H, V1.8B, V2.8B
	WORD $0x6e25c083 // UMULL2 V3.8H, V4.16B, V5.16B
	WORD $0x2e68c0e6 // UMULL V6.4S, V7.4H, V8.4H
	WORD $0x6e6bc149 // UMULL2 V9.4S, V10.8H, V11.8H
	WORD $0x2eaec1ac // UMULL V12.2D, V13.2S, V14.2S
	WORD $0x6eb1c20f // UMULL2 V15.2D, V16.4S, V17.4S
	WORD $0x2f74aa72 // UMULL V18.4S, V19.4H, V4.H[7]
	WORD $0x6f75aab4 // UMULL2 V20.4S, V21.8H, V5.H[7]
	WORD $0x2fb8aaf6 // UMULL V22.2D, V23.2S, V24.S[3]
	WORD $0x6fbbab59 // UMULL2 V25.2D, V26.4S, V27.S[3]
	RET
`

func TestTranslateARM64RawUMULLCompleteAdvancedSIMDFormats(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64RawUMULLForms, true)
	file, err := Parse(ArchARM64, arm64RawUMULLForms)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"rawumullforms": {Name: "rawumullforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"zext <8 x i8>", "zext <4 x i16>", "zext <2 x i32>",
				"mul <8 x i16>", "mul <4 x i32>", "mul <2 x i64>",
				"extractelement <8 x i16>", "extractelement <4 x i32>",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 raw UMULL lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-umull.ll", "arm64-raw-umull.o", ll)
		})
	}
}

func TestARM64RawUMULLRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawumull(SB),$0-24
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	MOVD out+16(FP), R2
	VLD1 (R0), [V0.S4]
	VLD1 (R1), [V1.S4]
	WORD $0x2ea1c01e // UMULL V30.2D, V0.2S, V1.2S
	WORD $0x6ea1c01f // UMULL2 V31.2D, V0.4S, V1.4S
	VST1 [V30.D2, V31.D2], (R2)
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
			"rawumull": {
				Name: "rawumull", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
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
extern void rawumull(const uint32_t *, const uint32_t *, uint64_t *);
int main(void) {
  const uint32_t a[4] = {0xffffffffu, 2, 3, 0x80000000u};
  const uint32_t b[4] = {2, 0xffffffffu, 7, 2};
  uint64_t got[4] = {0};
  const uint64_t want[4] = {UINT64_C(0x1fffffffe), UINT64_C(0x1fffffffe), 21, UINT64_C(0x100000000)};
  rawumull(a, b, got);
  for (int i = 0; i < 4; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_umull", triple, ll, mainC, nil)
}

func TestARM64RawUMULLDecoderRejectsAdjacentSMULLEncoding(t *testing.T) {
	if _, ok := decodeARM64RawUMULL(0x0e22c020); ok {
		t.Fatal("UMULL decoder claimed adjacent SMULL encoding")
	}
}
