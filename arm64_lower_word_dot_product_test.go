package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64RawDotProductCompleteArchitecturalFormats(t *testing.T) {
	vectorBases := []uint32{
		0x0e809400, // SDOT.
		0x2e809400, // UDOT.
		0x0e809c00, // USDOT.
	}
	indexedBases := []uint32{
		0x0f80e000, // SDOT (by element).
		0x2f80e000, // UDOT (by element).
		0x0f80f000, // USDOT (by element).
		0x0f00f000, // SUDOT (by element; no vector form exists).
	}
	var source strings.Builder
	source.WriteString("TEXT rawdotproductforms(SB),$0-0\n")
	for _, base := range vectorBases {
		for _, q := range []uint32{0, 1 << 30} {
			fmt.Fprintf(&source, "\tWORD $%#08x\n", base|q|31<<16|30<<5|29)
		}
	}
	for _, base := range indexedBases {
		for _, q := range []uint32{0, 1 << 30} {
			for lane := uint32(0); lane < 4; lane++ {
				laneBits := (lane&1)<<21 | (lane&2)<<10
				fmt.Fprintf(&source, "\tWORD $%#08x\n", base|q|laneBits|31<<16|30<<5|29)
			}
		}
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"rawdotproductforms": {Name: "rawdotproductforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"sext <", "zext <", "mul <", "add i32"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("raw dot-product lowering omitted %q:\n%s", want, ir)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-dot-product.ll", "arm64-raw-dot-product.o", ir)
		})
	}
}

func TestARM64RawDotProductDecoderRejectsAdjacentAndReservedEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x0ea09400, // Reserved size bit in SDOT (vector).
		0x2e809c00, // Unallocated U bit in USDOT (vector).
		0x2f00f000, // Unallocated U bit in SUDOT (by element).
		0x0f40e000, // Unallocated size in SDOT (by element).
		0x0fc0e000, // Unallocated size in SDOT (by element).
		0x0f80e400, // Reserved bit 10 in SDOT (by element).
	} {
		if _, ok := decodeARM64RawDotProduct(word); ok {
			t.Fatalf("dot-product decoder accepted adjacent/reserved encoding %#08x", word)
		}
	}
}

func TestARM64RawDotProductRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawdotproduct(SB),$0-32
	MOVD accumulator+0(FP), R0
	MOVD lhs+8(FP), R1
	MOVD rhs+16(FP), R2
	MOVD output+24(FP), R3
	VLD1 (R1), [V1.B16]
	VLD1 (R2), [V2.B16]
	VLD1 (R0), [V3.S4]
	WORD $0x4e829423 // SDOT V3.4S, V1.16B, V2.16B
	VST1 [V3.S4], (R3)
	ADD $16, R3
	VLD1 (R0), [V4.S4]
	WORD $0x6e829424 // UDOT V4.4S, V1.16B, V2.16B
	VST1 [V4.S4], (R3)
	ADD $16, R3
	VLD1 (R0), [V5.S4]
	WORD $0x4e829c25 // USDOT V5.4S, V1.16B, V2.16B
	VST1 [V5.S4], (R3)
	ADD $16, R3
	VLD1 (R0), [V6.S4]
	WORD $0x4f82e826 // SDOT V6.4S, V1.16B, V2.4B[2]
	VST1 [V6.S4], (R3)
	ADD $16, R3
	VLD1 (R0), [V7.S4]
	WORD $0x6f82e827 // UDOT V7.4S, V1.16B, V2.4B[2]
	VST1 [V7.S4], (R3)
	ADD $16, R3
	VLD1 (R0), [V8.S4]
	WORD $0x4f82f828 // USDOT V8.4S, V1.16B, V2.4B[2]
	VST1 [V8.S4], (R3)
	ADD $16, R3
	VLD1 (R0), [V9.S4]
	WORD $0x4f02f829 // SUDOT V9.4S, V1.16B, V2.4B[2]
	VST1 [V9.S4], (R3)
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
		Sigs: map[string]FuncSig{
			"rawdotproduct": {
				Name: "rawdotproduct", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr}, Ret: Void,
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
extern void rawdotproduct(const int32_t *, const int8_t *, const int8_t *, int32_t *);
int main(void) {
  const int32_t accumulator[4] = {10, 20, 30, 40};
  const int8_t lhs[16] = {-1,2,-3,4, -1,2,-3,4, -1,2,-3,4, -1,2,-3,4};
  const int8_t rhs[16] = {1,2,3,4, 9,10,11,12, 5,-6,7,-8, 13,14,15,16};
	  const int32_t want[28] = {
	    20,46,-40,74, 1044,5166,4568,7242, 1044,5166,3032,7242,
	    -60,-50,-40,-30, 4548,4558,4568,4578, 3012,3022,3032,3042,
    1476,1486,1496,1506,
  };
  int32_t got[28] = {0};
  rawdotproduct(accumulator, lhs, rhs, got);
  for (int i = 0; i < 28; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_dot_product", triple, ir, mainC, nil)
}
