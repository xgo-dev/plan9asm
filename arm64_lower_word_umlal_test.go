package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

const arm64RawUMLALForms = `
TEXT rawumlalforms(SB),$0-0
	WORD $0x2e228020 // UMLAL  V0.8H, V1.8B, V2.8B
	WORD $0x6e258083 // UMLAL2 V3.8H, V4.16B, V5.16B
	WORD $0x2e6880e6 // UMLAL  V6.4S, V7.4H, V8.4H
	WORD $0x6e6b8149 // UMLAL2 V9.4S, V10.8H, V11.8H
	WORD $0x2eae81ac // UMLAL  V12.2D, V13.2S, V14.2S
	WORD $0x6eb1820f // UMLAL2 V15.2D, V16.4S, V17.4S
	RET
`

func TestTranslateARM64RawUMLALCompleteAdvancedSIMDFormats(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64RawUMLALForms, true)
	file, err := Parse(ArchARM64, arm64RawUMLALForms)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"rawumlalforms": {Name: "rawumlalforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"zext <8 x i8>", "zext <4 x i16>", "zext <2 x i32>",
				"mul <8 x i16>", "mul <4 x i32>", "mul <2 x i64>", "add <",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 raw UMLAL lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-umlal.ll", "arm64-raw-umlal.o", ll)
		})
	}
}

func TestARM64RawUMLALRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawumlal(SB),$0-32
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	MOVD accumulator+16(FP), R2
	MOVD out+24(FP), R3
	VLD1 (R0), [V0.B16]
	VLD1 (R1), [V1.B16]
	VLD1 (R2), [V2.H8, V3.H8]
	WORD $0x2e218002 // UMLAL  V2.8H, V0.8B, V1.8B
	WORD $0x6e218003 // UMLAL2 V3.8H, V0.16B, V1.16B
	VST1 [V2.H8, V3.H8], (R3)
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
			"rawumlal": {
				Name: "rawumlal", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
					{Offset: 24, Type: Ptr, Index: 3, Field: -1},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void rawumlal(const uint8_t *, const uint8_t *, const uint16_t *, uint16_t *);
int main(void) {
  uint8_t a[16], b[16];
  uint16_t accumulator[16], got[16] = {0};
  for (int i = 0; i < 16; i++) {
    a[i] = (uint8_t)(240+i);
    b[i] = (uint8_t)(17-i);
    accumulator[i] = (uint16_t)(65000+i);
  }
  rawumlal(a, b, accumulator, got);
  for (int i = 0; i < 16; i++) {
    uint16_t want = (uint16_t)(accumulator[i] + (uint16_t)a[i] * (uint16_t)b[i]);
    if (got[i] != want) return i + 1;
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_umlal", triple, ll, mainC, nil)
}

func TestARM64RawUMLALDecoderRejectsAdjacentEncodings(t *testing.T) {
	for _, word := range []uint32{0x0e228020, 0x2e22a020} { // SMLAL, UMLSL.
		t.Run(fmt.Sprintf("%#08x", word), func(t *testing.T) {
			if _, ok := decodeARM64RawUMLAL(word); ok {
				t.Fatalf("UMLAL decoder claimed adjacent encoding %#08x", word)
			}
		})
	}
}
