package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64RawPairwiseAddLongCompleteArchitecturalFormats(t *testing.T) {
	bases := []uint32{
		0x0e202800, // SADDLP.
		0x2e202800, // UADDLP.
		0x0e206800, // SADALP.
		0x2e206800, // UADALP.
	}
	var source strings.Builder
	source.WriteString("TEXT rawpairwiseaddlongforms(SB),$0-0\n")
	for _, base := range bases {
		for size := uint32(0); size < 3; size++ {
			for q := uint32(0); q < 2; q++ {
				fmt.Fprintf(&source, "\tWORD $%#08x\n", base|size<<22|q<<30|31<<5|30)
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
				Sigs: map[string]FuncSig{
					"rawpairwiseaddlongforms": {Name: "rawpairwiseaddlongforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-pairwise-add-long.ll", "arm64-raw-pairwise-add-long.o", ir)
		})
	}
}

func TestARM64RawPairwiseAddLongDecoderRejectsAdjacentAndReservedEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x0ee02800, // SADDLP reserved 64-bit source elements.
		0x2ee02800, // UADDLP reserved 64-bit source elements.
		0x0ee06800, // SADALP reserved 64-bit source elements.
		0x2ee06800, // UADALP reserved 64-bit source elements.
		0x0e202c00, // adjacent opcode bits.
		0x0e203800, // SADDV.
	} {
		if _, ok := decodeARM64RawPairwiseAddLong(word); ok {
			t.Fatalf("pairwise-add-long decoder accepted adjacent/reserved encoding %#08x", word)
		}
	}
}

func TestARM64RawPairwiseAddLongRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawpairwiseaddlong(SB),$0-24
	MOVD input+0(FP), R0
	MOVD accumulator+8(FP), R1
	MOVD output+16(FP), R2
	VLD1 (R0), [V0.B16]
	VLD1 (R1), [V4.H8]
	VLD1 (R1), [V5.H8]
	WORD $0x4e202801 // SADDLP V1.8H, V0.16B
	WORD $0x6e202802 // UADDLP V2.8H, V0.16B
	WORD $0x4e206804 // SADALP V4.8H, V0.16B
	WORD $0x6e206805 // UADALP V5.8H, V0.16B
	VST1.P [V1.H8], 16(R2)
	VST1.P [V2.H8], 16(R2)
	VST1.P [V4.H8], 16(R2)
	VST1 [V5.H8], (R2)
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
			"rawpairwiseaddlong": {
				Name: "rawpairwiseaddlong", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
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
extern void rawpairwiseaddlong(const uint8_t *, const int16_t *, int16_t *);
int main(void) {
  const uint8_t input[16] = {255,1,2,3,128,127,254,255,10,20,30,40,50,60,70,80};
  const int16_t accumulator[8] = {100,100,100,100,100,100,100,100};
  const int16_t signed_sum[8] = {0,5,-1,-3,30,70,110,150};
  const int16_t unsigned_sum[8] = {256,5,255,509,30,70,110,150};
  int16_t got[32] = {0};
  rawpairwiseaddlong(input, accumulator, got);
  for (int lane = 0; lane < 8; lane++) {
    if (got[lane] != signed_sum[lane]) return 1 + lane;
    if (got[8 + lane] != unsigned_sum[lane]) return 10 + lane;
    if (got[16 + lane] != signed_sum[lane] + 100) return 20 + lane;
    if (got[24 + lane] != unsigned_sum[lane] + 100) return 30 + lane;
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_pairwise_add_long", triple, ir, mainC, nil)
}
