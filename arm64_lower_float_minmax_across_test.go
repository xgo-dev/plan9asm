package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

type arm64RawFloatMinMaxAcrossEncodingTest struct {
	base      uint32
	operation string
	bits      int
	lanes     int
}

var arm64RawFloatMinMaxAcrossEncodingTests = []arm64RawFloatMinMaxAcrossEncodingTest{
	{0x0e30c800, "maxnum", 16, 4},
	{0x4e30c800, "maxnum", 16, 8},
	{0x6e30c800, "maxnum", 32, 4},
	{0x0eb0c800, "minnum", 16, 4},
	{0x4eb0c800, "minnum", 16, 8},
	{0x6eb0c800, "minnum", 32, 4},
	{0x0e30f800, "maximum", 16, 4},
	{0x4e30f800, "maximum", 16, 8},
	{0x6e30f800, "maximum", 32, 4},
	{0x0eb0f800, "minimum", 16, 4},
	{0x4eb0f800, "minimum", 16, 8},
	{0x6eb0f800, "minimum", 32, 4},
}

func TestARM64RawFloatMinMaxAcrossDecoderCompleteArchitectureFamily(t *testing.T) {
	count := 0
	for _, encoding := range arm64RawFloatMinMaxAcrossEncodingTests {
		for source := 0; source < 32; source++ {
			for destination := 0; destination < 32; destination++ {
				word := encoding.base | uint32(source)<<5 | uint32(destination)
				form, ok := decodeARM64RawFloatMinMaxAcross(word)
				if !ok {
					t.Fatalf("decoder rejected %#08x", word)
				}
				if form.operation != encoding.operation ||
					form.arrangement != (arm64VectorArrangement{elementBits: encoding.bits, lanes: encoding.lanes}) ||
					form.source != source || form.destination != destination {
					t.Fatalf("decode %#08x = %+v", word, form)
				}
				count++
			}
		}
	}
	if count != 12288 {
		t.Fatalf("covered %d floating min/max-across encodings, want 12288", count)
	}
}

func TestTranslateARM64RawFloatMinMaxAcrossCompleteArchitectureFamily(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawfloatminmaxacrossarchitecturefamily(SB),$0-0\n")
	for _, encoding := range arm64RawFloatMinMaxAcrossEncodingTests {
		fmt.Fprintf(&source, "\tWORD $%#08x\n", encoding.base|2<<5|1)
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
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"rawfloatminmaxacrossarchitecturefamily": {Name: "rawfloatminmaxacrossarchitecturefamily", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"@llvm.maximum.f16", "@llvm.minimum.f16", "@llvm.maxnum.f16", "@llvm.minnum.f16",
				"@llvm.maximum.f32", "@llvm.minimum.f32", "@llvm.maxnum.f32", "@llvm.minnum.f32",
				`"target-features"="+fullfp16"`,
			} {
				if !strings.Contains(ir, want) {
					t.Fatalf("raw float min/max-across IR omitted %q:\n%s", want, ir)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-float-minmax-across.ll", "arm64-raw-float-minmax-across.o", ir)
		})
	}
}

const arm64VectorFloatMinMaxAcrossForms = `
TEXT vectorfloatminmaxacrossforms(SB),$0-0
	VFMAXV V0.S4, V1
	VFMINV V2.S4, V3
	VFMAXNMV V4.S4, V5
	VFMINNMV V6.S4, V7
	RET
`

func TestTranslateARM64VectorFloatMinMaxAcrossCompleteGoAssemblerForms(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64VectorFloatMinMaxAcrossForms, true)
	file, err := Parse(ArchARM64, arm64VectorFloatMinMaxAcrossForms)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"vectorfloatminmaxacrossforms": {Name: "vectorfloatminmaxacrossforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, intrinsic := range []string{"@llvm.maximum.f32", "@llvm.minimum.f32", "@llvm.maxnum.f32", "@llvm.minnum.f32"} {
				if !strings.Contains(ir, intrinsic) {
					t.Fatalf("ARM64 float min/max-across omitted %s:\n%s", intrinsic, ir)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-vector-float-minmax-across.ll", "arm64-vector-float-minmax-across.o", ir)
		})
	}
}

func TestTranslateARM64VectorFloatMinMaxAcrossRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VFMAXV V0.S2, V1",
		"VFMINV V0.D2, V1",
		"VFMAXNMV V0.H8, V1",
		"VFMINNMV V0.S4, V1.D2",
		"VFMAXV V0.S4",
		"VFMINV.P V0.S4, V1",
	} {
		t.Run(strings.NewReplacer(" ", "_", ",", "", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badvectorfloatminmaxacross(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64",
				Sigs: map[string]FuncSig{"badvectorfloatminmaxacross": {Name: "badvectorfloatminmaxacross", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's float min/max-across forms", instruction)
			}
		})
	}
}

func TestARM64VectorFloatMinMaxAcrossRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT vectorfloatminmaxacross(SB),$0-16
	MOVD input+0(FP), R0
	MOVD output+8(FP), R1
	VLD1 (R0), [V0.S4]
	VFMAXV V0.S4, V1
	VFMINV V0.S4, V2
	VFMAXNMV V0.S4, V3
	VFMINNMV V0.S4, V4
	FMOVS F1, 0(R1)
	FMOVS F2, 4(R1)
	FMOVS F3, 8(R1)
	FMOVS F4, 12(R1)
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
			"vectorfloatminmaxacross": {
				Name: "vectorfloatminmaxacross", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
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
extern void vectorfloatminmaxacross(const float *, float *);
int main(void) {
  const float input[4] = {-2.0f, 7.0f, 3.0f, 1.0f};
  const float want[4] = {7.0f, -2.0f, 7.0f, -2.0f};
  float got[4] = {0};
  vectorfloatminmaxacross(input, got);
  for (int i = 0; i < 4; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_vector_float_minmax_across", triple, ir, mainC, nil)
}

func TestARM64RawFloatMinMaxAcrossHalfRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawfloatminmaxacrosshalf(SB),$0-16
	MOVD input+0(FP), R0
	MOVD output+8(FP), R1
	VLD1 (R0), [V0.H8]
	WORD $0x4e30c801 // FMAXNMV H1, V0.8H
	WORD $0x4eb0c802 // FMINNMV H2, V0.8H
	WORD $0x4e30f803 // FMAXV H3, V0.8H
	WORD $0x4eb0f804 // FMINV H4, V0.8H
	VST1.P [V1.H8, V2.H8, V3.H8, V4.H8], 64(R1)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{
			"rawfloatminmaxacrosshalf": {
				Name: "rawfloatminmaxacrosshalf", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
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
extern void rawfloatminmaxacrosshalf(const uint16_t *, uint16_t *);
int main(void) {
  const uint16_t input[8] = {0xc000,0x4700,0x4200,0x3c00,0xbc00,0x4400,0x4000,0x0000};
  uint16_t got[32] = {0};
  rawfloatminmaxacrosshalf(input, got);
  if (got[0] != 0x4700 || got[8] != 0xc000 || got[16] != 0x4700 || got[24] != 0xc000) return 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_float_minmax_across_half", triple, ir, mainC, nil)
}

func TestARM64RawFloatMinMaxAcrossUsesNamedFamily(t *testing.T) {
	const source = `
TEXT rawfloatminmaxacross(SB),$0-0
	WORD $0x6e30f800
	WORD $0x6eb0f800
	WORD $0x6e30c800
	WORD $0x6eb0c800
	RET
`
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64",
		Sigs: map[string]FuncSig{"rawfloatminmaxacross": {Name: "rawfloatminmaxacross", Ret: Void}},
	}); err != nil {
		t.Fatal(err)
	}
}
