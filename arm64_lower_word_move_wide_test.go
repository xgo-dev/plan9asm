package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

type arm64RawMoveWideTestForm struct {
	op    Op
	opc   uint32
	width int
	shift int
}

func arm64RawMoveWideForms() []arm64RawMoveWideTestForm {
	var forms []arm64RawMoveWideTestForm
	for _, operation := range []struct {
		op  Op
		opc uint32
	}{{"MOVN", 0}, {"MOVZ", 2}, {"MOVK", 3}} {
		for _, width := range []int{32, 64} {
			maxShift := width - 16
			for shift := 0; shift <= maxShift; shift += 16 {
				forms = append(forms, arm64RawMoveWideTestForm{op: operation.op, opc: operation.opc, width: width, shift: shift})
			}
		}
	}
	return forms
}

func encodeARM64RawMoveWide(opc uint32, width, shift int, immediate uint16, destination int) uint32 {
	word := uint32(0x12800000) | opc<<29 | uint32(shift/16)<<21 | uint32(immediate)<<5 | uint32(destination)
	if width == 64 {
		word |= 1 << 31
	}
	return word
}

func TestTranslateARM64RawMoveWideCompleteFormats(t *testing.T) {
	forms := arm64RawMoveWideForms()
	if len(forms) != 18 {
		t.Fatalf("move-wide format inventory has %d forms, want 18", len(forms))
	}
	var source strings.Builder
	source.WriteString("TEXT rawmovewideforms(SB),$0-0\n")
	for i, form := range forms {
		fmt.Fprintf(&source, "\tWORD $%#08x\n", encodeARM64RawMoveWide(form.opc, form.width, form.shift, 0xa55a, i%31))
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
				Sigs:         map[string]FuncSig{"rawmovewideforms": {Name: "rawmovewideforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-move-wide.ll", "arm64-raw-move-wide.o", ll)
		})
	}
}

func TestARM64RawMoveWideDecoderCoversEveryImmediate(t *testing.T) {
	for _, form := range arm64RawMoveWideForms() {
		for immediate := 0; immediate <= 0xffff; immediate++ {
			word := encodeARM64RawMoveWide(form.opc, form.width, form.shift, uint16(immediate), 17)
			got, ok := decodeARM64RawMoveWide(word)
			if !ok {
				t.Fatalf("decoder rejected %s width=%d shift=%d immediate=%#04x", form.op, form.width, form.shift, immediate)
			}
			if got.op != form.op || got.width != form.width || got.shift != form.shift || got.immediate != uint16(immediate) || got.destination != 17 {
				t.Fatalf("decoded word %#08x as %+v, want %+v immediate=%#04x destination=17", word, got, form, immediate)
			}
		}
	}
}

func TestARM64RawMoveWideRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	var source strings.Builder
	source.WriteString("TEXT rawmovewide(SB),$0-16\n\tMOVD out+0(FP), R0\n\tMOVD initial+8(FP), R1\n")
	fmt.Fprintf(&source, "\tWORD $%#08x\n", encodeARM64RawMoveWide(2, 64, 32, 0x1234, 2)) // MOVZ X2, #0x1234, LSL #32.
	fmt.Fprintf(&source, "\tWORD $%#08x\n", encodeARM64RawMoveWide(0, 32, 16, 0x00ff, 3)) // MOVN W3, #0x00ff, LSL #16.
	fmt.Fprintf(&source, "\tWORD $%#08x\n", encodeARM64RawMoveWide(3, 64, 16, 0xabcd, 1)) // MOVK X1, #0xabcd, LSL #16.
	source.WriteString("\tMOVD R2, 0(R0)\n\tMOVD R3, 8(R0)\n\tMOVD R1, 16(R0)\n\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{"rawmovewide": {
			Name: "rawmovewide", Args: []LLVMType{Ptr, I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: I64, Index: 1, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void rawmovewide(uint64_t *, uint64_t);
int main(void) {
  uint64_t got[3] = {0};
  rawmovewide(got, UINT64_C(0x0123456789abcdef));
  if (got[0] != UINT64_C(0x0000123400000000)) return 1;
  if (got[1] != UINT64_C(0x00000000ff00ffff)) return 2;
  if (got[2] != UINT64_C(0x01234567abcdcdef)) return 3;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_move_wide", triple, ll, mainC, nil)
}

func TestARM64RawMoveWideDecoderRejectsReservedAndAdjacentEncodings(t *testing.T) {
	for _, word := range []uint32{
		encodeARM64RawMoveWide(1, 64, 0, 1, 0),  // reserved opc.
		encodeARM64RawMoveWide(2, 32, 32, 1, 0), // reserved W shift.
		0x12000000,                              // AND immediate.
	} {
		if _, ok := decodeARM64RawMoveWide(word); ok {
			t.Fatalf("move-wide decoder accepted reserved/adjacent encoding %#08x", word)
		}
	}
}
