package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

// These encodings cover every Advanced SIMD SQDMULH format documented by
// LLVM 22's AArch64 assembler: scalar, vector, scalar-by-element, and
// vector-by-element, for every legal H/S arrangement and Q width.
const arm64RawSQDMULHForms = `
TEXT rawsqdmulhforms(SB),$0-0
	WORD $0x5e62b420 // SQDMULH H0, H1, H2
	WORD $0x5ea5b483 // SQDMULH S3, S4, S5
	WORD $0x0e68b4e6 // SQDMULH V6.4H, V7.4H, V8.4H
	WORD $0x4e6bb549 // SQDMULH V9.8H, V10.8H, V11.8H
	WORD $0x0eaeb5ac // SQDMULH V12.2S, V13.2S, V14.2S
	WORD $0x4eb1b60f // SQDMULH V15.4S, V16.4S, V17.4S
	WORD $0x5f74ca72 // SQDMULH H18, H19, V4.H[7]
	WORD $0x5fb7cad5 // SQDMULH S21, S22, V23.S[3]
	WORD $0x0f7acb38 // SQDMULH V24.4H, V25.4H, V10.H[7]
	WORD $0x4f7dcb9b // SQDMULH V27.8H, V28.8H, V13.H[7]
	WORD $0x0fa1c81e // SQDMULH V30.2S, V0.2S, V1.S[3]
	WORD $0x4fa4c862 // SQDMULH V2.4S, V3.4S, V4.S[3]
	RET
`

func TestTranslateARM64RawSQDMULHCompleteAdvancedSIMDFormats(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64RawSQDMULHForms, true)
	file, err := Parse(ArchARM64, arm64RawSQDMULHForms)
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
				Sigs: map[string]FuncSig{
					"rawsqdmulhforms": {Name: "rawsqdmulhforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"mul <4 x i32>", "mul <8 x i32>",
				"mul <2 x i64>", "mul <4 x i64>",
				"ashr <4 x i32>", "ashr <8 x i32>",
				"ashr <2 x i64>", "ashr <4 x i64>",
				"select <", "i16 32767", "i32 2147483647",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 raw SQDMULH lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-sqdmulh.ll", "arm64-raw-sqdmulh.o", ll)
		})
	}
}

func TestARM64RawSQDMULHRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawsqdmulh(SB),$0-24
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	MOVD out+16(FP), R2
	VLD1 (R0), [V0.S4]
	VLD1 (R1), [V1.S4]
	WORD $0x4ea1b402 // SQDMULH V2.4S, V0.4S, V1.4S
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
			"rawsqdmulh": {
				Name: "rawsqdmulh", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
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
#include <limits.h>
extern void rawsqdmulh(const int32_t *, const int32_t *, int32_t *);
int main(void) {
  const int32_t a[4] = {INT32_MIN, INT32_MIN, 1073741824, -1073741824};
  const int32_t b[4] = {INT32_MIN, INT32_MAX, 1073741824, 1073741824};
  int32_t got[4] = {0};
  rawsqdmulh(a, b, got);
  const int32_t want[4] = {INT32_MAX, -2147483647, 536870912, -536870912};
  for (int i = 0; i < 4; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_sqdmulh", triple, ll, mainC, nil)
}

func TestARM64RawSQDMULHDecoderRejectsAdjacentEncodings(t *testing.T) {
	// SQRDMULH has different rounding semantics and must not be captured by the
	// SQDMULH masks merely because the register fields are identical.
	const word = uint32(0x6ea1b402)
	if _, ok := decodeARM64RawSQDMULH(word); ok {
		t.Fatal("SQDMULH decoder accepted adjacent SQRDMULH encoding")
	}
}
