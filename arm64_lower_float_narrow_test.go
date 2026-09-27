package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64VectorFloatNarrowCompleteGoAssemblerForms(t *testing.T) {
	const source = `
TEXT vectorfloatnarrowforms(SB),$0-0
	VFCVTN V2.S4, V3.H4
	VFCVTN2 V4.S4, V5.H8
	VFCVTN V0.D2, V31.S2
	VFCVTN2 V30.D2, V1.S4
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"vectorfloatnarrowforms": {Name: "vectorfloatnarrowforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"fptrunc <4 x float>", "fptrunc <2 x double>"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("ARM64 VFCVTN family omitted %q:\n%s", want, ir)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-vector-float-narrow.ll", "arm64-vector-float-narrow.o", ir)
		})
	}
}

func TestTranslateARM64RawVectorFloatNarrowCompleteBaseFormats(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawvectorfloatnarrowforms(SB),$0-0\n")
	for _, size := range []uint32{0, 1 << 22} { // 4S -> 4H and 2D -> 2S.
		for _, upper := range []uint32{0, 1 << 30} { // FCVTN and FCVTN2.
			fmt.Fprintf(&source, "\tWORD $%#08x\n", uint32(0x0e216800)|size|upper|30<<5|29)
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
				Sigs: map[string]FuncSig{"rawvectorfloatnarrowforms": {Name: "rawvectorfloatnarrowforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"fptrunc <4 x float>", "fptrunc <2 x double>"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("raw floating narrow omitted %q:\n%s", want, ir)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-vector-float-narrow.ll", "arm64-raw-vector-float-narrow.o", ir)
		})
	}
}

func TestARM64RawVectorFloatNarrowDecoderRejectsAdjacentEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x2e216800, // FCVTXN, not FCVTN.
		0x0ea16800, // Unallocated size.
		0x0e217800, // FCVTL, not FCVTN.
		0x0e216c00, // Adjacent opcode.
	} {
		if _, ok := decodeARM64RawVectorFloatNarrow(word); ok {
			t.Fatalf("floating narrow decoder accepted adjacent encoding %#08x", word)
		}
	}
}

func TestTranslateARM64VectorFloatNarrowRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{
		"VFCVTN V0.D2",
		"VFCVTN V0.D2, V1.S4",
		"VFCVTN2 V0.D2, V1.S2",
		"VFCVTN V0.S2, V1.H4",
		"VFCVTN2 V0.S4, V1.S4",
		"VFCVTN.P V0.D2, V1.S2",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			source := "TEXT badvectorfloatnarrow(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64",
				Sigs: map[string]FuncSig{"badvectorfloatnarrow": {Name: "badvectorfloatnarrow", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's VFCVTN/VFCVTN2 optab", instruction)
			}
		})
	}
}

func TestARM64RawVectorFloatNarrowRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawvectorfloatnarrow(SB),$0-16
	MOVD input+0(FP), R0
	MOVD output+8(FP), R1
	ADD $16, R1, R2
	VLD1 (R0), [V1.S4]
	VLD1 (R2), [V2.H8]
	WORD $0x0e216820 // FCVTN V0.4H, V1.4S
	VST1 [V0.H8], (R1)
	WORD $0x4e216822 // FCVTN2 V2.8H, V1.4S
	VST1 [V2.H8], (R2)
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
			"rawvectorfloatnarrow": {
				Name: "rawvectorfloatnarrow", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
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
extern void rawvectorfloatnarrow(const float *, uint16_t *);
int main(void) {
  const float input[4] = {1.0f, -2.0f, 0.5f, 65504.0f};
  const uint16_t want[16] = {
    0x3c00,0xc000,0x3800,0x7bff, 0,0,0,0,
    1,2,3,4, 0x3c00,0xc000,0x3800,0x7bff,
  };
  uint16_t got[16] = {0,0,0,0,0,0,0,0, 1,2,3,4,5,6,7,8};
  rawvectorfloatnarrow(input, got);
  for (int i = 0; i < 16; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_vector_float_narrow", triple, ir, mainC, nil)
}
