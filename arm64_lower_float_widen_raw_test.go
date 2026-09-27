package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64RawVectorFloatWidenCompleteBaseFormats(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawvectorfloatwidenforms(SB),$0-0\n")
	for _, size := range []uint32{0, 1 << 22} { // 4H -> 4S and 2S -> 2D.
		for _, upper := range []uint32{0, 1 << 30} { // FCVTL and FCVTL2.
			fmt.Fprintf(&source, "\tWORD $%#08x\n", uint32(0x0e217800)|size|upper|30<<5|29)
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
				Sigs: map[string]FuncSig{"rawvectorfloatwidenforms": {Name: "rawvectorfloatwidenforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"fpext <4 x half>", "fpext <2 x float>"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("raw floating widen omitted %q:\n%s", want, ir)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-vector-float-widen.ll", "arm64-raw-vector-float-widen.o", ir)
		})
	}
}

func TestARM64RawVectorFloatWidenDecoderRejectsAdjacentEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x2e217800, // U bit is unallocated for FCVTL.
		0x0ea17800, // Unallocated size.
		0x0e216800, // FCVTN, not FCVTL.
		0x0e217c00, // Adjacent opcode.
	} {
		if _, ok := decodeARM64RawVectorFloatWiden(word); ok {
			t.Fatalf("floating widen decoder accepted adjacent encoding %#08x", word)
		}
	}
}

func TestARM64RawVectorFloatWidenRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawvectorfloatwiden(SB),$0-16
	MOVD input+0(FP), R0
	MOVD output+8(FP), R1
	ADD $16, R1, R2
	VLD1 (R0), [V1.H8]
	WORD $0x0e217822 // FCVTL V1.4H, V2.4S
	VST1 [V2.S4], (R1)
	WORD $0x4e217823 // FCVTL2 V1.8H, V3.4S
	VST1 [V3.S4], (R2)
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
			"rawvectorfloatwiden": {
				Name: "rawvectorfloatwiden", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
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
extern void rawvectorfloatwiden(const uint16_t *, uint32_t *);
int main(void) {
  const uint16_t input[8] = {0x3c00,0xc000,0x3800,0x7bff, 0x8000,0x7c00,0xfc00,0x3400};
  const uint32_t want[8] = {0x3f800000,0xc0000000,0x3f000000,0x477fe000, 0x80000000,0x7f800000,0xff800000,0x3e800000};
  uint32_t got[8] = {0};
  rawvectorfloatwiden(input, got);
  for (int i = 0; i < 8; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_vector_float_widen", triple, ir, mainC, nil)
}
