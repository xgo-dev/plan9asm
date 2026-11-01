package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

// Integer MUL has six same-vector forms and four by-element forms in the
// Advanced SIMD ISA. Go's VMUL mnemonic covers the former; raw WORD users can
// encode both groups, so the raw decoder must cover the complete family.
const arm64RawMULForms = `
TEXT rawmulforms(SB),$0-0
	WORD $0x0e229c20 // MUL V0.8B, V1.8B, V2.8B
	WORD $0x4e259c83 // MUL V3.16B, V4.16B, V5.16B
	WORD $0x0e689ce6 // MUL V6.4H, V7.4H, V8.4H
	WORD $0x4e6b9d49 // MUL V9.8H, V10.8H, V11.8H
	WORD $0x0eae9dac // MUL V12.2S, V13.2S, V14.2S
	WORD $0x4eb19e0f // MUL V15.4S, V16.4S, V17.4S
	WORD $0x0f748a72 // MUL V18.4H, V19.4H, V4.H[7]
	WORD $0x4f758ab4 // MUL V20.8H, V21.8H, V5.H[7]
	WORD $0x0fb88af6 // MUL V22.2S, V23.2S, V24.S[3]
	WORD $0x4fbb8b59 // MUL V25.4S, V26.4S, V27.S[3]
	RET
`

func TestTranslateARM64RawMULCompleteAdvancedSIMDFormats(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64RawMULForms, true)
	file, err := Parse(ArchARM64, arm64RawMULForms)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs:         map[string]FuncSig{"rawmulforms": {Name: "rawmulforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"mul <8 x i8>", "mul <16 x i8>",
				"mul <4 x i16>", "mul <8 x i16>",
				"mul <2 x i32>", "mul <4 x i32>",
				"extractelement <8 x i16>", "extractelement <4 x i32>",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 raw MUL lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-mul.ll", "arm64-raw-mul.o", ll)
		})
	}
}

func TestARM64RawMULRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawmul(SB),$0-24
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	MOVD out+16(FP), R2
	VLD1 (R0), [V0.S4]
	VLD1 (R1), [V1.S4]
	WORD $0x4ea19c02 // MUL V2.4S, V0.4S, V1.4S
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
		TargetTriple: triple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{
			"rawmul": {
				Name: "rawmul", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
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
extern void rawmul(const uint32_t *, const uint32_t *, uint32_t *);
int main(void) {
  const uint32_t a[4] = {0, 1, 0xffffffffu, 0x80000000u};
  const uint32_t b[4] = {7, 0xffffffffu, 3, 2};
  uint32_t got[4] = {0};
  const uint32_t want[4] = {0, 0xffffffffu, 0xfffffffdu, 0};
  rawmul(a, b, got);
  for (int i = 0; i < 4; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_mul", triple, ll, mainC, nil)
}

func TestARM64RawMULDecoderRejectsAdjacentEncoding(t *testing.T) {
	// PMUL shares much of the three-same encoding space but has polynomial,
	// rather than integer, multiplication semantics.
	if _, ok := decodeARM64RawMUL(0x2e229c20); ok {
		t.Fatal("MUL decoder claimed adjacent PMUL encoding")
	}
}
