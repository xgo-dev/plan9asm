package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

type arm64RawModifiedImmediateTestForm struct {
	op          Op
	opBit       uint32
	cmode       uint32
	q           uint32
	arrangement arm64VectorArrangement
}

func arm64RawMOVIMVNIForms() []arm64RawModifiedImmediateTestForm {
	var forms []arm64RawModifiedImmediateTestForm
	addQForms := func(op Op, opBit, cmode uint32, elementBits int) {
		for _, q := range []uint32{0, 1} {
			vectorBits := 64
			if q != 0 {
				vectorBits = 128
			}
			forms = append(forms, arm64RawModifiedImmediateTestForm{
				op: op, opBit: opBit, cmode: cmode, q: q,
				arrangement: arm64VectorArrangement{elementBits: elementBits, lanes: vectorBits / elementBits},
			})
		}
	}
	for _, cmode := range []uint32{0, 2, 4, 6, 12, 13} { // S LSL and MSL forms.
		addQForms("VMOVI", 0, cmode, 32)
		addQForms("VMVNI", 1, cmode, 32)
	}
	for _, cmode := range []uint32{8, 10} { // H LSL forms.
		addQForms("VMOVI", 0, cmode, 16)
		addQForms("VMVNI", 1, cmode, 16)
	}
	addQForms("VMOVI", 0, 14, 8) // B replicated immediate.
	forms = append(forms,
		arm64RawModifiedImmediateTestForm{op: "VMOVI", opBit: 1, cmode: 14, q: 0, arrangement: arm64VectorArrangement{elementBits: 64, lanes: 1}},
		arm64RawModifiedImmediateTestForm{op: "VMOVI", opBit: 1, cmode: 14, q: 1, arrangement: arm64VectorArrangement{elementBits: 64, lanes: 2}},
	)
	return forms
}

func arm64RawORRBICForms() []arm64RawModifiedImmediateTestForm {
	var forms []arm64RawModifiedImmediateTestForm
	for _, op := range []struct {
		name  Op
		opBit uint32
	}{{"VORR", 0}, {"VBIC", 1}} {
		for _, cmode := range []uint32{1, 3, 5, 7, 9, 11} {
			bits := 32
			if cmode >= 8 {
				bits = 16
			}
			for _, q := range []uint32{0, 1} {
				vectorBits := 64
				if q != 0 {
					vectorBits = 128
				}
				forms = append(forms, arm64RawModifiedImmediateTestForm{
					op: op.name, opBit: op.opBit, cmode: cmode, q: q,
					arrangement: arm64VectorArrangement{elementBits: bits, lanes: vectorBits / bits},
				})
			}
		}
	}
	return forms
}

func encodeARM64RawModifiedImmediate(opBit, cmode, q uint32, immediate byte, destination int) uint32 {
	return 0x0f000400 | q<<30 | opBit<<29 | uint32(immediate>>5)<<16 | cmode<<12 | uint32(immediate&31)<<5 | uint32(destination)
}

func TestTranslateARM64RawMOVIMVNICompleteAdvancedSIMDFormats(t *testing.T) {
	forms := arm64RawMOVIMVNIForms()
	if len(forms) != 36 {
		t.Fatalf("MOVI/MVNI format inventory has %d forms, want 36", len(forms))
	}
	var source strings.Builder
	source.WriteString("TEXT rawmodifiedimmediateforms(SB),$0-0\n")
	for i, form := range forms {
		fmt.Fprintf(&source, "\tWORD $%#08x\n", encodeARM64RawModifiedImmediate(form.opBit, form.cmode, form.q, 0x92, i%32))
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs:         map[string]FuncSig{"rawmodifiedimmediateforms": {Name: "rawmodifiedimmediateforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-modified-immediate.ll", "arm64-raw-modified-immediate.o", ll)
		})
	}
}

func TestARM64RawMOVIMVNIDecoderCoversEveryImmediate(t *testing.T) {
	for _, form := range arm64RawMOVIMVNIForms() {
		for immediate := 0; immediate <= 255; immediate++ {
			word := encodeARM64RawModifiedImmediate(form.opBit, form.cmode, form.q, byte(immediate), 17)
			got, ok := decodeARM64RawModifiedImmediate(word)
			if !ok {
				t.Fatalf("decoder rejected %s cmode=%d Q=%d immediate=%#02x word=%#08x", form.op, form.cmode, form.q, immediate, word)
			}
			if got.op != form.op || got.arrangement != form.arrangement || got.destination != 17 {
				t.Fatalf("decoded word %#08x as %+v, want op=%s arrangement=%+v destination=17", word, got, form.op, form.arrangement)
			}
		}
	}
}

func TestTranslateARM64RawORRBICCompleteAdvancedSIMDFormats(t *testing.T) {
	forms := arm64RawORRBICForms()
	if len(forms) != 24 {
		t.Fatalf("ORR/BIC immediate format inventory has %d forms, want 24", len(forms))
	}
	var source strings.Builder
	source.WriteString("TEXT raworrbicforms(SB),$0-0\n")
	for i, form := range forms {
		fmt.Fprintf(&source, "\tWORD $%#08x\n", encodeARM64RawModifiedImmediate(form.opBit, form.cmode, form.q, 0x92, i%32))
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs:         map[string]FuncSig{"raworrbicforms": {Name: "raworrbicforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"and <2 x i32>", "or <2 x i32>", "and <8 x i16>", "or <8 x i16>"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("missing %q in %s:\n%s", want, triple, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-orr-bic-immediate.ll", "arm64-orr-bic-immediate.o", ll)
		})
	}
}

func TestARM64RawORRBICDecoderCoversEveryImmediate(t *testing.T) {
	for _, form := range arm64RawORRBICForms() {
		for immediate := 0; immediate <= 255; immediate++ {
			word := encodeARM64RawModifiedImmediate(form.opBit, form.cmode, form.q, byte(immediate), 17)
			got, ok := decodeARM64RawModifiedImmediate(word)
			if !ok || got.op != form.op || got.arrangement != form.arrangement || got.destination != 17 {
				t.Fatalf("decoded %s cmode=%d Q=%d immediate=%#02x word=%#08x as %+v, ok=%v",
					form.op, form.cmode, form.q, immediate, word, got, ok)
			}
		}
	}
}

func TestARM64RawORRBICRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	var source strings.Builder
	source.WriteString("TEXT raworrbic(SB),$0-8\n\tMOVD out+0(FP), R0\n")
	for _, step := range []struct {
		opBit, cmode, q uint32
		immediate       byte
		destination     int
	}{
		{0, 14, 1, 0x00, 0}, // Initialize V0 to zero.
		{0, 14, 1, 0x0f, 1}, // Initialize V1 to 0x0f bytes.
		{0, 3, 1, 0x55, 0},  // ORR 0x55 << 8 in every S lane.
		{1, 3, 1, 0x11, 0},  // BIC 0x11 << 8, leaving 0x44.
		{0, 9, 1, 0x80, 1},  // ORR 0x80 in every H lane.
		{1, 9, 1, 0x08, 1},  // BIC 0x08, leaving 0x87.
	} {
		fmt.Fprintf(&source, "\tWORD $%#08x\n", encodeARM64RawModifiedImmediate(step.opBit, step.cmode, step.q, step.immediate, step.destination))
	}
	source.WriteString("\tVST1 [V0.B16, V1.B16], (R0)\n\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{"raworrbic": {
			Name: "raworrbic", Args: []LLVMType{Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void raworrbic(uint8_t *);
int main(void) {
  uint8_t got[32] = {0};
  raworrbic(got);
  for (int i = 0; i < 16; i++) {
    if (got[i] != ((i & 3) == 1 ? 0x44 : 0)) return i + 1;
    if (got[16+i] != ((i & 1) == 0 ? 0x87 : 0x0f)) return i + 17;
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_orr_bic", triple, ll, mainC, nil)
}

func TestARM64RawMOVIMVNIRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	tests := []struct{ opBit, cmode, q uint32 }{
		{0, 14, 1}, // MOVI B16.
		{0, 10, 1}, // MOVI H8, LSL #8.
		{0, 6, 1},  // MOVI S4, LSL #24.
		{0, 12, 1}, // MOVI S4, MSL #8.
		{0, 13, 1}, // MOVI S4, MSL #16.
		{1, 10, 1}, // MVNI H8, LSL #8.
		{1, 13, 1}, // MVNI S4, MSL #16.
		{1, 14, 1}, // MOVI D2 byte mask.
	}
	var source strings.Builder
	source.WriteString("TEXT rawmodifiedimmediate(SB),$0-8\n\tMOVD out+0(FP), R0\n")
	for destination, test := range tests {
		fmt.Fprintf(&source, "\tWORD $%#08x\n", encodeARM64RawModifiedImmediate(test.opBit, test.cmode, test.q, 0x12, destination))
	}
	source.WriteString("\tVST1.P [V0.B16, V1.B16, V2.B16, V3.B16], 64(R0)\n\tVST1 [V4.B16, V5.B16, V6.B16, V7.B16], (R0)\n\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{"rawmodifiedimmediate": {
			Name: "rawmodifiedimmediate", Args: []LLVMType{Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void rawmodifiedimmediate(uint8_t *);
int main(void) {
  uint8_t got[128] = {0};
  rawmodifiedimmediate(got);
  for (int i = 0; i < 16; i++) {
    const uint8_t want[8] = {
      0x12,
      (i&1) ? 0x12 : 0x00,
      (i&3) == 3 ? 0x12 : 0x00,
      (i&3) == 0 ? 0xff : (i&3) == 1 ? 0x12 : 0x00,
      (i&3) < 2 ? 0xff : (i&3) == 2 ? 0x12 : 0x00,
      (i&1) ? 0xed : 0xff,
      (i&3) < 2 ? 0x00 : (i&3) == 2 ? 0xed : 0xff,
	      (0x12u & (1u << (i&7))) ? 0xff : 0x00,
    };
    for (int op = 0; op < 8; op++) if (got[op*16+i] != want[op]) return op*16+i+1;
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_modified_immediate", triple, ll, mainC, nil)
}

func TestARM64RawModifiedImmediateDecoderRejectsFloatingNeighbor(t *testing.T) {
	for _, word := range []uint32{
		encodeARM64RawModifiedImmediate(0, 15, 1, 1, 0), // FMOV immediate.
		encodeARM64RawModifiedImmediate(1, 15, 0, 1, 0), // Reserved encoding.
	} {
		if _, ok := decodeARM64RawModifiedImmediate(word); ok {
			t.Fatalf("modified-immediate decoder accepted neighboring encoding %#08x", word)
		}
	}
}
