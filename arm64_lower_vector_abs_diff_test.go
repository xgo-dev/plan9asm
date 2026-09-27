package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64RawVectorAbsoluteDifferenceCompleteArchitecturalFormats(t *testing.T) {
	ops := []struct {
		name  string
		bases []uint32
	}{
		{"sabd", []uint32{0x0e207400, 0x4e207400, 0x0e607400, 0x4e607400, 0x0ea07400, 0x4ea07400}},
		{"uabd", []uint32{0x2e207400, 0x6e207400, 0x2e607400, 0x6e607400, 0x2ea07400, 0x6ea07400}},
		{"saba", []uint32{0x0e207c00, 0x4e207c00, 0x0e607c00, 0x4e607c00, 0x0ea07c00, 0x4ea07c00}},
		{"uaba", []uint32{0x2e207c00, 0x6e207c00, 0x2e607c00, 0x6e607c00, 0x2ea07c00, 0x6ea07c00}},
	}
	var source strings.Builder
	source.WriteString("TEXT vectorabsolutedifferenceforms(SB),$0-0\n")
	for _, op := range ops {
		for _, base := range op.bases {
			fmt.Fprintf(&source, "\tWORD $%#08x // %s\n", base|29<<16|30<<5|28, op.name)
		}
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
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
				Sigs: map[string]FuncSig{"vectorabsolutedifferenceforms": {Name: "vectorabsolutedifferenceforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"sext <", "icmp sgt <", "icmp ugt <", "add <"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("absolute-difference family for %s omitted %q:\n%s", triple, want, ir)
				}
			}
			compileLLVMToObject(t, llc, triple, "arm64-vector-absolute-difference.ll", "arm64-vector-absolute-difference.o", ir)
		})
	}
}

func TestTranslateARM64RawVectorAbsoluteDifferenceLongForms(t *testing.T) {
	const source = `TEXT vectorabsoluteDifferenceLong(SB),$0-0
	WORD $0x2e217004 // UABDL V4.8H, V0.8B, V1.8B
	WORD $0x6e217005 // UABDL2 V5.8H, V0.16B, V1.16B
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		TargetTriple: arm64LinuxGNUTriple,
		Goarch:       "arm64",
		Sigs:         map[string]FuncSig{"vectorabsoluteDifferenceLong": {Name: "vectorabsoluteDifferenceLong", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "zext <8 x i8>") || !strings.Contains(ir, "icmp ugt <8 x i16>") {
		t.Fatalf("unsigned absolute-difference-long lowering omitted widened compare:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, arm64LinuxGNUTriple, "arm64-vector-absolute-difference-long.ll", "arm64-vector-absolute-difference-long.o", ir)
}

func TestARM64RawVectorAbsoluteDifferenceRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT vectorabsolutedifference(SB),$0-32
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	MOVD accumulator+16(FP), R2
	MOVD output+24(FP), R3
	VLD1 (R0), [V0.B16]
	VLD1 (R1), [V1.B16]
	VLD1 (R2), [V2.B16]
	VLD1 (R2), [V5.B16]
	WORD $0x4e217403 // SABD V3.16B, V0.16B, V1.16B
	WORD $0x6e217404 // UABD V4.16B, V0.16B, V1.16B
	WORD $0x4e217c02 // SABA V2.16B, V0.16B, V1.16B
	WORD $0x6e217c05 // UABA V5.16B, V0.16B, V1.16B
	VST1.P [V3.B16], 16(R3)
	VST1.P [V4.B16], 16(R3)
	VST1.P [V2.B16], 16(R3)
	VST1.P [V5.B16], 16(R3)
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
		Sigs: map[string]FuncSig{"vectorabsolutedifference": {
			Name: "vectorabsolutedifference", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr}, Ret: Void,
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
extern void vectorabsolutedifference(const int8_t *, const int8_t *, const uint8_t *, uint8_t *);
int main(void) {
  const int8_t a[16] = {127,-128,12,-20,0,1,-1,64,-64,100,-100,5,-5,30,-30,42};
  const int8_t b[16] = {-128,127,-12,20,0,-1,1,-64,64,-100,100,-5,5,-30,30,-42};
  const uint8_t accumulator[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
  uint8_t got[64] = {0};
  vectorabsolutedifference(a, b, accumulator, got);
  for (int i = 0; i < 16; i++) {
    int signed_diff = (int)a[i] - (int)b[i];
    if (signed_diff < 0) signed_diff = -signed_diff;
    int unsigned_diff = (int)(uint8_t)a[i] - (int)(uint8_t)b[i];
    if (unsigned_diff < 0) unsigned_diff = -unsigned_diff;
    if (got[i] != (uint8_t)signed_diff) return i + 1;
    if (got[16+i] != (uint8_t)unsigned_diff) return i + 17;
    if (got[32+i] != (uint8_t)(accumulator[i] + signed_diff)) return i + 33;
    if (got[48+i] != (uint8_t)(accumulator[i] + unsigned_diff)) return i + 49;
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_vector_absolute_difference", triple, ir, mainC, nil)
}
