package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64VectorWideningMultiplyCompleteGoAssemblerForms(t *testing.T) {
	type form struct{ narrow, wide string }
	lowForms := []form{{"B8", "H8"}, {"H4", "S4"}, {"S2", "D2"}}
	highForms := []form{{"B16", "H8"}, {"H8", "S4"}, {"S4", "D2"}}
	var source strings.Builder
	source.WriteString("TEXT ·vectorWideningMultiplyForms(SB), $0-0\n")
	for _, op := range []string{"VSMULL", "VSMLAL", "VSMLSL", "VUMULL", "VUMLAL", "VUMLSL"} {
		for _, form := range lowForms {
			fmt.Fprintf(&source, "\t%s V0.%s, V1.%s, V31.%s\n", op, form.narrow, form.narrow, form.wide)
		}
		for _, form := range highForms {
			fmt.Fprintf(&source, "\t%s2 V2.%s, V3.%s, V30.%s\n", op, form.narrow, form.narrow, form.wide)
		}
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)

	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		file, err := Parse(ArchARM64, source.String())
		if err != nil {
			t.Fatal(err)
		}
		ll, err := Translate(file, Options{
			TargetTriple: triple,
			Goarch:       "arm64",
			ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
			Sigs: map[string]FuncSig{
				"vectorWideningMultiplyForms": {Name: "vectorWideningMultiplyForms", Ret: Void},
			},
		})
		if err != nil {
			t.Fatalf("%s: %v", triple, err)
		}
		for _, want := range []string{"sext <", "zext <", "mul <", "add <", "sub <", "shufflevector <"} {
			if !strings.Contains(ll, want) {
				t.Fatalf("%s widening-multiply IR omitted %q:\n%s", triple, want, ll)
			}
		}
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc not found")
		}
		compileLLVMToObject(t, llc, triple, "arm64-vector-widening-multiply.ll", "arm64-vector-widening-multiply.o", ll)
	}
}

func TestTranslateARM64RawWideningMultiplyByElementCompleteArchitecturalForms(t *testing.T) {
	type operation struct {
		name string
		base uint32
	}
	operations := []operation{
		{"SMLAL", 0x0f002000}, {"SMLAL2", 0x4f002000},
		{"SMLSL", 0x0f006000}, {"SMLSL2", 0x4f006000},
		{"SMULL", 0x0f00a000}, {"SMULL2", 0x4f00a000},
		{"UMLAL", 0x2f002000}, {"UMLAL2", 0x6f002000},
		{"UMLSL", 0x2f006000}, {"UMLSL2", 0x6f006000},
		{"UMULL", 0x2f00a000}, {"UMULL2", 0x6f00a000},
	}
	var source strings.Builder
	source.WriteString("TEXT rawwideningmultiplyelementforms(SB),$0-0\n")
	for _, operation := range operations {
		for _, size := range []int{1, 2} {
			laneCount := 8
			laneRegister := 15
			if size == 2 {
				laneCount = 4
				laneRegister = 31
			}
			for lane := 0; lane < laneCount; lane++ {
				word := encodeARM64RawWideningMultiplyByElement(operation.base, size, lane, 30, laneRegister, 29)
				if strings.HasPrefix(operation.name, "UMULL") {
					form, ok := decodeARM64RawUMULL(word)
					if !ok || !form.byElement || form.element != lane || form.first != 30 || form.second != laneRegister || form.destReg != 29 {
						t.Fatalf("decode UMULL by-element %#08x = %#v, %v; want lane=%d first=30 second=%d destination=29", word, form, ok, lane, laneRegister)
					}
				}
				fmt.Fprintf(&source, "\tWORD $%#08x // %s size=%d lane=%d\n", word, operation.name, size, lane)
			}
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
				Sigs: map[string]FuncSig{"rawwideningmultiplyelementforms": {Name: "rawwideningmultiplyelementforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"extractelement <8 x i16>", "extractelement <4 x i32>", "sext <", "zext <", "mul <", "add <", "sub <"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("raw widening-multiply by-element family for %s omitted %q:\n%s", triple, want, ir)
				}
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-widening-multiply-element.ll", "arm64-raw-widening-multiply-element.o", ir)
		})
	}
}

func encodeARM64RawWideningMultiplyByElement(base uint32, size, lane, sourceReg, laneReg, destinationReg int) uint32 {
	word := base | uint32(size)<<22 | uint32(sourceReg)<<5 | uint32(destinationReg)
	if size == 1 {
		word |= uint32(laneReg&15) << 16
		word |= uint32(lane&1) << 20
		word |= uint32((lane>>1)&1) << 21
		word |= uint32((lane>>2)&1) << 11
		return word
	}
	word |= uint32(laneReg&15) << 16
	word |= uint32((laneReg>>4)&1) << 20
	word |= uint32(lane&1) << 21
	word |= uint32((lane>>1)&1) << 11
	return word
}

func TestARM64RawWideningMultiplyByElementRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	words := []uint32{
		encodeARM64RawWideningMultiplyByElement(0x0f002000, 1, 0, 0, 1, 2), // SMLAL H4.
		encodeARM64RawWideningMultiplyByElement(0x4f002000, 1, 7, 0, 1, 2), // SMLAL2 H8.
		encodeARM64RawWideningMultiplyByElement(0x2f006000, 2, 3, 0, 1, 2), // UMLSL S2.
		encodeARM64RawWideningMultiplyByElement(0x6f00a000, 2, 2, 0, 1, 2), // UMULL2 S4.
	}
	source := fmt.Sprintf(`
TEXT rawwideningmultiplyelement(SB),$0-32
	MOVD source+0(FP), R0
	MOVD elements+8(FP), R1
	MOVD accumulator+16(FP), R2
	MOVD output+24(FP), R3
	VLD1 (R0), [V0.B16]
	VLD1 (R1), [V1.B16]
	VLD1 (R2), [V2.B16]
	WORD $%#08x
	VST1 [V2.B16], (R3)
	ADD $16, R3
	VLD1 (R2), [V2.B16]
	WORD $%#08x
	VST1 [V2.B16], (R3)
	ADD $16, R3
	VLD1 (R2), [V2.B16]
	WORD $%#08x
	VST1 [V2.B16], (R3)
	ADD $16, R3
	VLD1 (R2), [V2.B16]
	WORD $%#08x
	VST1 [V2.B16], (R3)
	RET
`, words[0], words[1], words[2], words[3])
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir, err := Translate(file, Options{
		TargetTriple: triple, Goarch: "arm64",
		Sigs: map[string]FuncSig{"rawwideningmultiplyelement": {
			Name: "rawwideningmultiplyelement", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr}, Ret: Void,
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
#include <string.h>
extern void rawwideningmultiplyelement(const void *, const void *, const void *, void *);
int main(void) {
  const uint16_t source_h[8] = {0xffff,2,0xfffd,4,0xfffb,6,0xfff9,8};
  const uint16_t element_h[8] = {3,4,5,6,7,8,9,0xfff6};
  const uint32_t accumulator_s[4] = {10,20,30,40};
  uint8_t got[64] = {0};
  uint8_t want[64] = {0};
  rawwideningmultiplyelement(source_h, element_h, accumulator_s, got);
  int32_t *want_s0 = (int32_t *)(want + 0);
  int32_t *want_s1 = (int32_t *)(want + 16);
  for (int i = 0; i < 4; i++) {
    want_s0[i] = (int32_t)accumulator_s[i] + (int16_t)source_h[i] * (int16_t)element_h[0];
    want_s1[i] = (int32_t)accumulator_s[i] + (int16_t)source_h[i + 4] * (int16_t)element_h[7];
  }
  const uint32_t *source_s = (const uint32_t *)source_h;
  const uint32_t *element_s = (const uint32_t *)element_h;
  const uint64_t *accumulator_d = (const uint64_t *)accumulator_s;
  uint64_t *want_d0 = (uint64_t *)(want + 32);
  uint64_t *want_d1 = (uint64_t *)(want + 48);
  for (int i = 0; i < 2; i++) {
    want_d0[i] = accumulator_d[i] - (uint64_t)source_s[i] * element_s[3];
    want_d1[i] = (uint64_t)source_s[i + 2] * element_s[2];
  }
  for (int i = 0; i < 64; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_widening_multiply_element", triple, ir, mainC, nil)
}

func TestTranslateARM64VectorWideningMultiplyRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VUMULL V0.B16, V1.B16, V2.H8",
		"VUMULL2 V0.B8, V1.B8, V2.H8",
		"VUMLAL V0.H4, V1.H4, V2.H4",
		"VUMLSL V0.H8, V1.H8, V2.S4",
		"VSMULL V0.D1, V1.D1, V2.D2",
		"VSMLAL V0.S2, V1.S2, V2.S2",
		"VSMLSL2 V0.B8, V1.B8, V2.H8",
		"VUMULL.P V0.B8, V1.B8, V2.H8",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			source := "TEXT ·badVectorWideningMultiply(SB), $0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
				Sigs: map[string]FuncSig{
					"badVectorWideningMultiply": {Name: "badVectorWideningMultiply", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's vector widening-multiply forms", instruction)
			}
		})
	}
}
