package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

const arm64RawMatrixMultiplyForms = `
TEXT rawmatrixmultiplyforms(SB),$0-0
	WORD $0x4e9fa7dd // SMMLA V29.4S, V30.16B, V31.16B
	WORD $0x6e9fa7dd // UMMLA V29.4S, V30.16B, V31.16B
	WORD $0x4e9fafdd // USMMLA V29.4S, V30.16B, V31.16B
	RET
`

func TestTranslateARM64RawMatrixMultiplyCompleteArchitecturalFamily(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64RawMatrixMultiplyForms, true)
	file, err := Parse(ArchARM64, arm64RawMatrixMultiplyForms)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"rawmatrixmultiplyforms": {Name: "rawmatrixmultiplyforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"sext <16 x i8>", "zext <16 x i8>", "mul <16 x i32>", "add i32"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("raw matrix-multiply family for %s omitted %q:\n%s", triple, want, ir)
				}
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-matrix-multiply.ll", "arm64-raw-matrix-multiply.o", ir)
		})
	}
}

func TestARM64RawMatrixMultiplyDecoderRejectsAdjacentAndReservedEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x0e80a400, // Q=0 is unallocated for matrix multiply.
		0x4ea0a400, // Reserved bit 21.
		0x4e80a000, // Adjacent opcode field.
		0x4e80a800, // Adjacent opcode field.
		0x6e80ac00, // Unallocated unsigned/mixed-sign combination.
	} {
		if _, ok := decodeARM64RawMatrixMultiply(word); ok {
			t.Fatalf("matrix-multiply decoder accepted adjacent/reserved encoding %#08x", word)
		}
	}
}

func TestARM64RawMatrixMultiplyRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawmatrixmultiply(SB),$0-32
	MOVD accumulator+0(FP), R0
	MOVD lhs+8(FP), R1
	MOVD rhs+16(FP), R2
	MOVD output+24(FP), R3
	VLD1 (R1), [V16.B16]
	VLD1 (R2), [V18.B16]
	VLD1 (R0), [V8.S4]
	WORD $0x4e92a608 // SMMLA V8.4S, V16.16B, V18.16B
	VST1 [V8.S4], (R3)
	ADD $16, R3
	VLD1 (R0), [V8.S4]
	WORD $0x6e92a608 // UMMLA V8.4S, V16.16B, V18.16B
	VST1 [V8.S4], (R3)
	ADD $16, R3
	VLD1 (R0), [V8.S4]
	WORD $0x4e92ae08 // USMMLA V8.4S, V16.16B, V18.16B
	VST1 [V8.S4], (R3)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir, err := Translate(file, Options{
		TargetTriple: triple, Goarch: "arm64",
		Sigs: map[string]FuncSig{"rawmatrixmultiply": {
			Name: "rawmatrixmultiply", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				{Offset: 24, Type: Ptr, Index: 3, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void rawmatrixmultiply(const int32_t *, const uint8_t *, const uint8_t *, int32_t *);
static void reference(int32_t *out, const int32_t *acc, const uint8_t *lhs, const uint8_t *rhs, int lhs_signed, int rhs_signed) {
  for (int row = 0; row < 2; row++) for (int col = 0; col < 2; col++) {
    int32_t sum = acc[row * 2 + col];
    for (int k = 0; k < 8; k++) {
      int32_t a = lhs_signed ? (int8_t)lhs[row * 8 + k] : lhs[row * 8 + k];
      int32_t b = rhs_signed ? (int8_t)rhs[k * 2 + col] : rhs[k * 2 + col];
      sum += a * b;
    }
    out[row * 2 + col] = sum;
  }
}
int main(void) {
  const int32_t accumulator[4] = {10, 20, 30, 40};
  const uint8_t lhs[16] = {255,2,253,4,251,6,249,8, 247,10,245,12,243,14,241,16};
  const uint8_t rhs[16] = {1,254,3,252,5,250,7,248,9,246,11,244,13,242,15,240};
  int32_t got[12] = {0};
  int32_t want[12] = {0};
  rawmatrixmultiply(accumulator, lhs, rhs, got);
  reference(want + 0, accumulator, lhs, rhs, 1, 1);
  reference(want + 4, accumulator, lhs, rhs, 0, 0);
  reference(want + 8, accumulator, lhs, rhs, 0, 1);
  for (int i = 0; i < 12; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_matrix_multiply", triple, ir, mainC, nil)
}
