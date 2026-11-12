package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

const arm64RawUZPForms = `
TEXT rawuzpforms(SB),$0-0
	WORD $0x0e021820 // UZP1 V0.8B, V1.8B, V2.8B
	WORD $0x4e051883 // UZP1 V3.16B, V4.16B, V5.16B
	WORD $0x0e4818e6 // UZP1 V6.4H, V7.4H, V8.4H
	WORD $0x4e4b1949 // UZP1 V9.8H, V10.8H, V11.8H
	WORD $0x0e8e19ac // UZP1 V12.2S, V13.2S, V14.2S
	WORD $0x4e911a0f // UZP1 V15.4S, V16.4S, V17.4S
	WORD $0x4ed41a72 // UZP1 V18.2D, V19.2D, V20.2D
	WORD $0x0e025820 // UZP2 V0.8B, V1.8B, V2.8B
	WORD $0x4e055883 // UZP2 V3.16B, V4.16B, V5.16B
	WORD $0x0e4858e6 // UZP2 V6.4H, V7.4H, V8.4H
	WORD $0x4e4b5949 // UZP2 V9.8H, V10.8H, V11.8H
	WORD $0x0e8e59ac // UZP2 V12.2S, V13.2S, V14.2S
	WORD $0x4e915a0f // UZP2 V15.4S, V16.4S, V17.4S
	WORD $0x4ed45a72 // UZP2 V18.2D, V19.2D, V20.2D
	RET
`

func TestTranslateARM64RawUZPCompleteAdvancedSIMDFormats(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64RawUZPForms, true)
	file, err := Parse(ArchARM64, arm64RawUZPForms)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"rawuzpforms": {Name: "rawuzpforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Count(ll, "shufflevector"); got < 14 {
				t.Fatalf("raw UZP shuffle count = %d, want at least 14:\n%s", got, ll)
			}
			for _, want := range []string{"i32 0, i32 2", "i32 1, i32 3"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("raw UZP forms omitted %q mask:\n%s", want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-uzp.ll", "arm64-raw-uzp.o", ll)
		})
	}
}

func TestARM64RawUZPRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawuzp(SB),$0-24
	MOVD n+0(FP), R0
	MOVD m+8(FP), R1
	MOVD out+16(FP), R2
	VLD1 (R0), [V0.S4]
	VLD1 (R1), [V1.S4]
	WORD $0x4e811802 // UZP1 V2.4S, V0.4S, V1.4S
	WORD $0x4e815803 // UZP2 V3.4S, V0.4S, V1.4S
	VST1 [V2.S4, V3.S4], (R2)
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
			"rawuzp": {
				Name: "rawuzp", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
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
extern void rawuzp(const uint32_t *, const uint32_t *, uint32_t *);
int main(void) {
  const uint32_t n[4] = {0, 1, 2, 3};
  const uint32_t m[4] = {10, 11, 12, 13};
  const uint32_t want[8] = {0, 2, 10, 12, 1, 3, 11, 13};
  uint32_t got[8] = {0};
  rawuzp(n, m, got);
  for (int i = 0; i < 8; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_uzp", triple, ll, mainC, nil)
}

func TestARM64RawUZPDecoderRejectsAdjacentZIPEncoding(t *testing.T) {
	if _, ok := decodeARM64RawUZP(0x4e813802); ok {
		t.Fatal("UZP decoder claimed adjacent ZIP encoding")
	}
}
