package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

const arm64RawUSHLLForms = `
TEXT rawushllforms(SB),$0-0
	WORD $0x2f08a420 // USHLL  V0.8H, V1.8B, #0
	WORD $0x2f0fa462 // USHLL  V2.8H, V3.8B, #7
	WORD $0x2f10a4a4 // USHLL  V4.4S, V5.4H, #0
	WORD $0x2f1fa4e6 // USHLL  V6.4S, V7.4H, #15
	WORD $0x2f20a528 // USHLL  V8.2D, V9.2S, #0
	WORD $0x2f3fa56a // USHLL  V10.2D, V11.2S, #31
	WORD $0x6f08a5ac // USHLL2 V12.8H, V13.16B, #0
	WORD $0x6f0fa5ee // USHLL2 V14.8H, V15.16B, #7
	WORD $0x6f10a630 // USHLL2 V16.4S, V17.8H, #0
	WORD $0x6f1fa672 // USHLL2 V18.4S, V19.8H, #15
	WORD $0x6f20a6b4 // USHLL2 V20.2D, V21.4S, #0
	WORD $0x6f3fa6f6 // USHLL2 V22.2D, V23.4S, #31
	RET
`

func TestTranslateARM64RawUSHLLCompleteAdvancedSIMDFormats(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64RawUSHLLForms, true)
	file, err := Parse(ArchARM64, arm64RawUSHLLForms)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"rawushllforms": {Name: "rawushllforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"zext <8 x i8>", "zext <4 x i16>", "zext <2 x i32>", "shl <8 x i16>", "shl <4 x i32>", "shl <2 x i64>"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 raw USHLL lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-ushll.ll", "arm64-raw-ushll.o", ll)
		})
	}
}

func TestARM64RawUSHLLDecoderCoversEveryImmediate(t *testing.T) {
	for _, highHalf := range []bool{false, true} {
		for _, bits := range []int{8, 16, 32} {
			for shift := 0; shift < bits; shift++ {
				word := uint32(0x2f00a400) | uint32(bits+shift)<<16
				if highHalf {
					word |= 1 << 30
				}
				form, ok := decodeARM64RawUSHLL(word)
				if !ok || form.sourceArrangement.elementBits != bits || form.shift != shift || form.highHalf != highHalf {
					t.Fatalf("decode USHLL high=%v bits=%d shift=%d: form=%#v ok=%v", highHalf, bits, shift, form, ok)
				}
			}
		}
	}
}

func TestARM64RawUSHLLRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawushll(SB),$0-16
	MOVD in+0(FP), R0
	MOVD out+8(FP), R1
	VLD1 (R0), [V11.S2]
	WORD $0x2f38a57e // USHLL V30.2D, V11.2S, #24
	VST1 [V30.D2], (R1)
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
			"rawushll": {
				Name: "rawushll", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
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
extern void rawushll(const uint32_t *, uint64_t *);
int main(void) {
  const uint32_t in[2] = {0xffffffffu, 0x12345678u};
  const uint64_t want[2] = {0x00ffffffff000000ull, 0x0012345678000000ull};
  uint64_t got[2] = {0};
  rawushll(in, got);
  for (int i = 0; i < 2; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_ushll", triple, ll, mainC, nil)
}

func TestARM64RawUSHLLDecoderRejectsAdjacentSSHLL(t *testing.T) {
	if _, ok := decodeARM64RawUSHLL(0x0f08a420); ok {
		t.Fatal("USHLL decoder claimed adjacent SSHLL encoding")
	}
}
