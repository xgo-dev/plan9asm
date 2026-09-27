package plan9asm

import (
	"strings"
	"testing"
)

// LLVM 22's AArch64 assembler was used to enumerate every fixed-width
// Advanced SIMD SQRDMULH form: scalar, vector, scalar-by-element, and
// vector-by-element, for every legal H/S arrangement and Q width.
const arm64RawSQRDMULHForms = `
TEXT rawsqrdmulhforms(SB),$0-0
	WORD $0x7e62b420 // SQRDMULH H0, H1, H2
	WORD $0x7ea5b483 // SQRDMULH S3, S4, S5
	WORD $0x2e68b4e6 // SQRDMULH V6.4H, V7.4H, V8.4H
	WORD $0x6e6bb549 // SQRDMULH V9.8H, V10.8H, V11.8H
	WORD $0x2eaeb5ac // SQRDMULH V12.2S, V13.2S, V14.2S
	WORD $0x6eb1b60f // SQRDMULH V15.4S, V16.4S, V17.4S
	WORD $0x5f74da72 // SQRDMULH H18, H19, V4.H[7]
	WORD $0x5fb7dad5 // SQRDMULH S21, S22, V23.S[3]
	WORD $0x0f7adb38 // SQRDMULH V24.4H, V25.4H, V10.H[7]
	WORD $0x4f7ddb9b // SQRDMULH V27.8H, V28.8H, V13.H[7]
	WORD $0x0fa1d81e // SQRDMULH V30.2S, V0.2S, V1.S[3]
	WORD $0x4fa4d862 // SQRDMULH V2.4S, V3.4S, V4.S[3]
	RET
`

func TestTranslateARM64RawSQRDMULHCompleteAdvancedSIMDFormats(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64RawSQRDMULHForms, true)
	file, err := Parse(ArchARM64, arm64RawSQRDMULHForms)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"rawsqrdmulhforms": {Name: "rawsqrdmulhforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"mul <4 x i32>", "mul <8 x i32>",
				"mul <2 x i64>", "mul <4 x i64>",
				"add <4 x i32>", "add <8 x i32>",
				"add <2 x i64>", "add <4 x i64>",
				"ashr <", "select <", "i16 32767", "i32 2147483647",
			} {
				if !strings.Contains(ir, want) {
					t.Fatalf("ARM64 raw SQRDMULH lowering for %s omitted %q:\n%s", triple, want, ir)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-sqrdmulh.ll", "arm64-raw-sqrdmulh.o", ir)
		})
	}
}

func TestARM64RawSQRDMULHDecoderDoesNotCaptureSQDMULH(t *testing.T) {
	if _, ok := decodeARM64RawSQRDMULH(0x4ea1b402); ok {
		t.Fatal("SQRDMULH decoder accepted adjacent SQDMULH encoding")
	}
}
