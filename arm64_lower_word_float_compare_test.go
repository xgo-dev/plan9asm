package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

type arm64RawFloatCompareEncodingTest struct {
	base     uint32
	op       Op
	bits     int
	lanes    int
	zero     bool
	absolute bool
}

var arm64RawFloatCompareEncodingTests = []arm64RawFloatCompareEncodingTest{
	{0x0e402400, "VFCMEQ", 16, 4, false, false}, {0x4e402400, "VFCMEQ", 16, 8, false, false},
	{0x0e20e400, "VFCMEQ", 32, 2, false, false}, {0x4e20e400, "VFCMEQ", 32, 4, false, false}, {0x4e60e400, "VFCMEQ", 64, 2, false, false},
	{0x2e402400, "VFCMGE", 16, 4, false, false}, {0x6e402400, "VFCMGE", 16, 8, false, false},
	{0x2e20e400, "VFCMGE", 32, 2, false, false}, {0x6e20e400, "VFCMGE", 32, 4, false, false}, {0x6e60e400, "VFCMGE", 64, 2, false, false},
	{0x2ec02400, "VFCMGT", 16, 4, false, false}, {0x6ec02400, "VFCMGT", 16, 8, false, false},
	{0x2ea0e400, "VFCMGT", 32, 2, false, false}, {0x6ea0e400, "VFCMGT", 32, 4, false, false}, {0x6ee0e400, "VFCMGT", 64, 2, false, false},
	{0x2e402c00, "VFACGE", 16, 4, false, true}, {0x6e402c00, "VFACGE", 16, 8, false, true},
	{0x2e20ec00, "VFACGE", 32, 2, false, true}, {0x6e20ec00, "VFACGE", 32, 4, false, true}, {0x6e60ec00, "VFACGE", 64, 2, false, true},
	{0x2ec02c00, "VFACGT", 16, 4, false, true}, {0x6ec02c00, "VFACGT", 16, 8, false, true},
	{0x2ea0ec00, "VFACGT", 32, 2, false, true}, {0x6ea0ec00, "VFACGT", 32, 4, false, true}, {0x6ee0ec00, "VFACGT", 64, 2, false, true},

	{0x0ef8d800, "VFCMEQ", 16, 4, true, false}, {0x4ef8d800, "VFCMEQ", 16, 8, true, false},
	{0x0ea0d800, "VFCMEQ", 32, 2, true, false}, {0x4ea0d800, "VFCMEQ", 32, 4, true, false}, {0x4ee0d800, "VFCMEQ", 64, 2, true, false},
	{0x2ef8c800, "VFCMGE", 16, 4, true, false}, {0x6ef8c800, "VFCMGE", 16, 8, true, false},
	{0x2ea0c800, "VFCMGE", 32, 2, true, false}, {0x6ea0c800, "VFCMGE", 32, 4, true, false}, {0x6ee0c800, "VFCMGE", 64, 2, true, false},
	{0x0ef8c800, "VFCMGT", 16, 4, true, false}, {0x4ef8c800, "VFCMGT", 16, 8, true, false},
	{0x0ea0c800, "VFCMGT", 32, 2, true, false}, {0x4ea0c800, "VFCMGT", 32, 4, true, false}, {0x4ee0c800, "VFCMGT", 64, 2, true, false},
	{0x2ef8d800, "VFCMLE", 16, 4, true, false}, {0x6ef8d800, "VFCMLE", 16, 8, true, false},
	{0x2ea0d800, "VFCMLE", 32, 2, true, false}, {0x6ea0d800, "VFCMLE", 32, 4, true, false}, {0x6ee0d800, "VFCMLE", 64, 2, true, false},
	{0x0ef8e800, "VFCMLT", 16, 4, true, false}, {0x4ef8e800, "VFCMLT", 16, 8, true, false},
	{0x0ea0e800, "VFCMLT", 32, 2, true, false}, {0x4ea0e800, "VFCMLT", 32, 4, true, false}, {0x4ee0e800, "VFCMLT", 64, 2, true, false},
}

func TestARM64RawFloatCompareDecoderCompleteArchitectureFamily(t *testing.T) {
	count := 0
	for _, encoding := range arm64RawFloatCompareEncodingTests {
		secondLimit := 32
		if encoding.zero {
			secondLimit = 1
		}
		for first := 0; first < 32; first++ {
			for second := 0; second < secondLimit; second++ {
				for destination := 0; destination < 32; destination++ {
					word := encoding.base | uint32(first)<<5 | uint32(destination)
					if !encoding.zero {
						word |= uint32(second) << 16
					}
					form, ok := decodeARM64RawFloatCompare(word)
					if !ok {
						t.Fatalf("decoder rejected %#08x", word)
					}
					if form.op != encoding.op || form.zero != encoding.zero || form.absolute != encoding.absolute ||
						form.arrangement != (arm64VectorArrangement{elementBits: encoding.bits, lanes: encoding.lanes}) ||
						form.first != first || form.destination != destination ||
						(!encoding.zero && form.second != second) {
						t.Fatalf("decode %#08x = %+v", word, form)
					}
					count++
				}
			}
		}
	}
	if count != 844800 {
		t.Fatalf("covered %d vector floating-compare encodings, want 844800", count)
	}
}

func TestTranslateARM64RawFloatCompareCompleteArchitectureFamily(t *testing.T) {
	const source = `
TEXT rawFloatCompareArchitectureFamily(SB),$0-0
	WORD $0x0e422420 // FCMEQ V0.4H, V1.4H, V2.4H
	WORD $0x6ec32405 // FCMGT V5.8H, V0.8H, V3.8H
	WORD $0x6e422c20 // FACGE V0.8H, V1.8H, V2.8H
	WORD $0x6ea2ec20 // FACGT V0.4S, V1.4S, V2.4S
	WORD $0x6ee2ec20 // FACGT V0.2D, V1.2D, V2.2D
	WORD $0x4ef8d820 // FCMEQ V0.8H, V1.8H, #0.0
	WORD $0x6ef8c820 // FCMGE V0.8H, V1.8H, #0.0
	WORD $0x4ef8c820 // FCMGT V0.8H, V1.8H, #0.0
	WORD $0x6ef8d820 // FCMLE V0.8H, V1.8H, #0.0
	WORD $0x4ef8e820 // FCMLT V0.8H, V1.8H, #0.0
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
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"rawFloatCompareArchitectureFamily": {Name: "rawFloatCompareArchitectureFamily", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"fcmp oeq <4 x half>", "fcmp ogt <8 x half>",
				"@llvm.fabs.v8f16", "@llvm.fabs.v4f32", "@llvm.fabs.v2f64",
				`"target-features"="+fullfp16"`,
			} {
				if !strings.Contains(ir, want) {
					t.Fatalf("raw vector floating-compare IR omitted %q:\n%s", want, ir)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-float-compare-family.ll", "arm64-raw-float-compare-family.o", ir)
		})
	}
}

func arm64FloatCompareCompleteSource(raw bool) string {
	arrangements := []struct {
		name     string
		modifier uint32
	}{
		{name: "S2"},
		{name: "S4", modifier: 1 << 30},
		{name: "D2", modifier: 1<<30 | 1<<22},
	}
	var source strings.Builder
	if raw {
		source.WriteString("TEXT rawfloatcompareforms(SB),$0-0\n")
		for _, base := range []uint32{0x0e20e400, 0x2e20e400, 0x2ea0e400} { // FCMEQ, FCMGE, FCMGT.
			for _, arrangement := range arrangements {
				fmt.Fprintf(&source, "\tWORD $%#08x\n", base|arrangement.modifier|1<<16|2<<5|3)
			}
		}
		for _, base := range []uint32{0x0ea0d800, 0x2ea0c800, 0x0ea0c800, 0x2ea0d800, 0x0ea0e800} { // FCMEQ/GE/GT/LE/LT zero.
			for _, arrangement := range arrangements {
				fmt.Fprintf(&source, "\tWORD $%#08x\n", base|arrangement.modifier|2<<5|3)
			}
		}
	} else {
		source.WriteString("TEXT floatcompareforms(SB),$0-0\n")
		for _, op := range []string{"VFCMEQ", "VFCMGE", "VFCMGT"} {
			for _, arrangement := range arrangements {
				fmt.Fprintf(&source, "\t%s V1.%s, V2.%s, V3.%s\n", op, arrangement.name, arrangement.name, arrangement.name)
			}
		}
		for _, op := range []string{"VFCMEQ", "VFCMGE", "VFCMGT", "VFCMLE", "VFCMLT"} {
			for _, arrangement := range arrangements {
				fmt.Fprintf(&source, "\t%s $(0.0), V2.%s, V3.%s\n", op, arrangement.name, arrangement.name)
			}
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64FloatCompareCompleteGo127Formats(t *testing.T) {
	for _, raw := range []bool{false, true} {
		name := "named"
		function := "floatcompareforms"
		if raw {
			name = "raw"
			function = "rawfloatcompareforms"
		}
		t.Run(name, func(t *testing.T) {
			source := arm64FloatCompareCompleteSource(raw)
			requireARM64GoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
				t.Run(triple, func(t *testing.T) {
					ll, err := Translate(file, Options{
						TargetTriple: triple,
						Goarch:       "arm64",
						Sigs:         map[string]FuncSig{function: {Name: function, Ret: Void}},
					})
					if err != nil {
						t.Fatal(err)
					}
					if got := strings.Count(ll, "fcmp o"); got != 24 {
						t.Fatalf("ARM64 %s float-compare lowering for %s emitted %d compares, want 24:\n%s", name, triple, got, ll)
					}
					llc := findLLVM22Tool("llc")
					if llc == "" {
						t.Fatal("LLVM 22 llc not found")
					}
					compileLLVMToObject(t, llc, triple, "arm64-"+name+"-float-compare.ll", "arm64-"+name+"-float-compare.o", ll)
				})
			}
		})
	}
}

func TestARM64RawFloatCompareRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawfloatcompare(SB),$0-24
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	MOVD out+16(FP), R2
	VLD1 (R0), [V0.S4]
	VLD1 (R1), [V1.S4]
	WORD $0x4e21e402 // FCMEQ V2.4S, V0.4S, V1.4S
	WORD $0x6e21e403 // FCMGE V3.4S, V0.4S, V1.4S
	WORD $0x6ea1e404 // FCMGT V4.4S, V0.4S, V1.4S
	WORD $0x4ea0d805 // FCMEQ V5.4S, V0.4S, #0.0
	WORD $0x6ea0c806 // FCMGE V6.4S, V0.4S, #0.0
	WORD $0x4ea0c807 // FCMGT V7.4S, V0.4S, #0.0
	WORD $0x6ea0d808 // FCMLE V8.4S, V0.4S, #0.0
	WORD $0x4ea0e809 // FCMLT V9.4S, V0.4S, #0.0
	VST1.P [V2.S4, V3.S4, V4.S4, V5.S4], 64(R2)
	VST1 [V6.S4, V7.S4, V8.S4, V9.S4], (R2)
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
		Sigs: map[string]FuncSig{"rawfloatcompare": {
			Name: "rawfloatcompare", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void rawfloatcompare(const float *, const float *, uint32_t *);
int main(void) {
  const float a[4] = {-2.0f, 0.0f, 3.0f, 4.0f};
  const float b[4] = {-2.0f, 1.0f, 2.0f, 5.0f};
  const unsigned truth[8][4] = {
    {1,0,0,0}, {1,0,1,0}, {0,0,1,0}, {0,1,0,0},
    {0,1,1,1}, {0,0,1,1}, {1,1,0,0}, {1,0,0,0},
  };
  uint32_t got[32] = {0};
  rawfloatcompare(a, b, got);
  for (int op = 0; op < 8; op++) for (int lane = 0; lane < 4; lane++)
    if (got[op*4+lane] != (truth[op][lane] ? UINT32_MAX : 0)) return op*4+lane+1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_float_compare", triple, ll, mainC, nil)
}

func TestARM64RawFloatCompareHalfAndAbsoluteRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawfloatcomparehalf(SB),$0-24
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	MOVD out+16(FP), R2
	VLD1 (R0), [V0.H8]
	VLD1 (R1), [V1.H8]
	WORD $0x6ec12402 // FCMGT V2.8H, V0.8H, V1.8H
	WORD $0x6e412c03 // FACGE V3.8H, V0.8H, V1.8H
	VST1 [V2.H8, V3.H8], (R2)
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
		Sigs: map[string]FuncSig{"rawfloatcomparehalf": {
			Name: "rawfloatcomparehalf", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void rawfloatcomparehalf(const uint16_t *, const uint16_t *, uint16_t *);
int main(void) {
  const uint16_t a[8] = {0xc000,0x0000,0x4200,0x4400,0xb800,0x7c00,0x8000,0x3c00};
  const uint16_t b[8] = {0xbc00,0x3c00,0x4000,0x4500,0x3400,0xfc00,0x0000,0xc000};
  const unsigned truth[2][8] = {
    {0,0,1,0,0,1,0,1},
    {1,0,1,0,1,1,1,0},
  };
  uint16_t got[16] = {0};
  rawfloatcomparehalf(a, b, got);
  for (int op = 0; op < 2; op++) for (int lane = 0; lane < 8; lane++)
    if (got[op*8+lane] != (truth[op][lane] ? UINT16_MAX : 0)) return op*8+lane+1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_float_compare_half", triple, ll, mainC, nil)
}

func TestARM64RawFloatCompareDecoderRejectsAdjacentAndReservedEncodings(t *testing.T) {
	for _, word := range []uint32{0x2e20d400, 0x1e21e400, 0x0e60e400, 0x0ee0d800} { // FADDP, scalar compare, binary D1, zero D1.
		if _, ok := decodeARM64RawFloatCompare(word); ok {
			t.Fatalf("float-compare decoder accepted adjacent/reserved encoding %#08x", word)
		}
	}
}
