package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

const arm64RawSSHRForms = `
TEXT rawsshrforms(SB),$0-0
	WORD $0x0f0f0420 // SSHR V0.8B, V1.8B, #1
	WORD $0x4f080462 // SSHR V2.16B, V3.16B, #8
	WORD $0x0f1f04a4 // SSHR V4.4H, V5.4H, #1
	WORD $0x4f1004e6 // SSHR V6.8H, V7.8H, #16
	WORD $0x0f3f0528 // SSHR V8.2S, V9.2S, #1
	WORD $0x4f20056a // SSHR V10.4S, V11.4S, #32
	WORD $0x4f4005ac // SSHR V12.2D, V13.2D, #64
	WORD $0x5f7f05ee // SSHR D14, D15, #1
	RET
`

func TestTranslateARM64RawSSHRCompleteAdvancedSIMDFormats(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64RawSSHRForms, true)
	file, err := Parse(ArchARM64, arm64RawSSHRForms)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"rawsshrforms": {Name: "rawsshrforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"ashr <8 x i8>", "ashr <16 x i8>",
				"ashr <4 x i16>", "ashr <8 x i16>",
				"ashr <2 x i32>", "ashr <4 x i32>",
				"ashr <2 x i64>", "ashr i64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 raw SSHR lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-sshr.ll", "arm64-raw-sshr.o", ll)
		})
	}
}

func TestARM64RawSSHRDecoderCoversEveryImmediate(t *testing.T) {
	for _, bits := range []int{8, 16, 32, 64} {
		for shift := 1; shift <= bits; shift++ {
			encodedImmediate := uint32(2*bits - shift)
			word := uint32(0x0f000400) | encodedImmediate<<16
			if bits == 64 {
				word |= 1 << 30
			}
			form, ok := decodeARM64RawSSHR(word)
			if !ok || form.arrangement.elementBits != bits || form.shift != shift {
				t.Fatalf("decode SSHR bits=%d shift=%d: form=%#v ok=%v", bits, shift, form, ok)
			}
		}
	}
}

func TestARM64RawSSHRRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawsshr(SB),$0-16
	MOVD in+0(FP), R0
	MOVD out+8(FP), R1
	VLD1 (R0), [V30.S4]
	WORD $0x4f2107de // SSHR V30.4S, V30.4S, #31
	VST1 [V30.S4], (R1)
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
			"rawsshr": {
				Name: "rawsshr", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
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
extern void rawsshr(const int32_t *, int32_t *);
int main(void) {
  const int32_t in[4] = {INT32_MIN, -1, 0, INT32_MAX};
  const int32_t want[4] = {-1, -1, 0, 0};
  int32_t got[4] = {0};
  rawsshr(in, got);
  for (int i = 0; i < 4; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_sshr", triple, ll, mainC, nil)
}

func TestARM64RawSSHRDecoderRejectsAdjacentUSHR(t *testing.T) {
	if _, ok := decodeARM64RawSSHR(0x2f0f0420); ok {
		t.Fatal("SSHR decoder claimed adjacent USHR encoding")
	}
}
