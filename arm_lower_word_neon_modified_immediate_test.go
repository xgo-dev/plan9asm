package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARMRawNEONModifiedImmediate(cmode int, invert, quad bool, destination, imm8 int) uint32 {
	word := uint32(0xf2800010 | (imm8>>7)<<24 | ((imm8>>4)&7)<<16 |
		(destination&15)<<12 | (destination/16)<<22 | cmode<<8 | imm8&15)
	if invert {
		word |= 1 << 5
	}
	if quad {
		word |= 1 << 6
	}
	return word
}

func TestARMRawNEONModifiedImmediateLLVM22Forms(t *testing.T) {
	for _, test := range []struct {
		word        uint32
		cmode       int
		invert      bool
		quad        bool
		destination int
		imm8        int
	}{
		{0xf2810e12, 14, false, false, 0, 0x12},
		{0xf2810e52, 14, false, true, 0, 0x12},
		{0xf2810812, 8, false, false, 0, 0x12},
		{0xf2810a12, 10, false, false, 0, 0x12},
		{0xf2810012, 0, false, false, 0, 0x12},
		{0xf2810212, 2, false, false, 0, 0x12},
		{0xf2810412, 4, false, false, 0, 0x12},
		{0xf2c0c651, 6, false, true, 28, 0x01},
		{0xf2810c12, 12, false, false, 0, 0x12},
		{0xf2810d12, 13, false, false, 0, 0x12},
		{0xf3820e3a, 14, true, false, 0, 0xaa},
		{0xf2810032, 0, true, false, 0, 0x12},
		{0xf2810832, 8, true, false, 0, 0x12},
		{0xf2870f10, 15, false, false, 0, 0x70},
	} {
		got, ok := decodeARMRawNEONModifiedImmediate(test.word)
		if !ok || got.cmode != test.cmode || got.invert != test.invert ||
			got.quad != test.quad || got.destination != test.destination || got.imm8 != test.imm8 {
			t.Fatalf("LLVM 22 encoding %#08x decoded as %+v, ok=%v", test.word, got, ok)
		}
		if encoded := encodeARMRawNEONModifiedImmediate(
			test.cmode, test.invert, test.quad, test.destination, test.imm8,
		); encoded != test.word {
			t.Fatalf("encoded %+v as %#08x, want %#08x", test, encoded, test.word)
		}
	}
}

func TestARMRawNEONModifiedImmediateAllFields(t *testing.T) {
	count := 0
	for _, cmode := range []int{0, 2, 4, 6, 8, 10, 12, 13, 14, 15} {
		for _, invert := range []bool{false, true} {
			if cmode == 15 && invert {
				continue
			}
			for _, quad := range []bool{false, true} {
				step := 1
				if quad {
					step = 2
				}
				for destination := 0; destination < 32; destination += step {
					for imm8 := 0; imm8 < 256; imm8++ {
						word := encodeARMRawNEONModifiedImmediate(
							cmode, invert, quad, destination, imm8,
						)
						got, ok := decodeARMRawNEONModifiedImmediate(word)
						if !ok || got.cmode != cmode || got.invert != invert ||
							got.quad != quad || got.destination != destination || got.imm8 != imm8 {
							t.Fatalf("encoding %#08x decoded as %+v, ok=%v", word, got, ok)
						}
						count++
					}
				}
			}
		}
	}
	if count != 233472 {
		t.Fatalf("covered %d VMOV/VMVN immediate forms, want 233472", count)
	}
}

func TestTranslateARMRawNEONModifiedImmediateAllFormatsLLVM22(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawModifiedImmediate(SB), $0-0\n")
	for _, cmode := range []int{0, 2, 4, 6, 8, 10, 12, 13, 14, 15} {
		for _, invert := range []bool{false, true} {
			if cmode == 15 && invert {
				continue
			}
			for _, quad := range []bool{false, true} {
				word := encodeARMRawNEONModifiedImmediate(cmode, invert, quad, 16, 0x12)
				fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
			}
		}
	}
	source.WriteString("\tRET\n")
	file, err := Parse(ArchARM, source.String())
	if err != nil {
		t.Fatal(err)
	}
	const triple = "armv7-unknown-linux-gnueabihf"
	ir, err := Translate(file, Options{
		Goarch: "arm", TargetTriple: triple,
		Sigs: map[string]FuncSig{"rawModifiedImmediate": {Name: "rawModifiedImmediate", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"bitcast <8 x i8>", "bitcast <4 x i16>", "bitcast <2 x i32>",
		"bitcast <1 x i64>", "bitcast <4 x i32>",
	} {
		if !strings.Contains(ir, fragment) {
			t.Fatalf("raw VMOV/VMVN modified immediate omitted %q:\n%s", fragment, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, triple, "arm-raw-neon-modified-immediate.ll", "arm-raw-neon-modified-immediate.o", ir)
}

func TestARMRawNEONModifiedImmediateExpandedValues(t *testing.T) {
	for _, test := range []struct {
		cmode  int
		invert bool
		imm8   int
		want   uint64
	}{
		{0, false, 0x12, 0x00000012},
		{2, false, 0x12, 0x00001200},
		{4, false, 0x12, 0x00120000},
		{6, false, 0x01, 0x01000000},
		{8, false, 0x12, 0x0012},
		{10, false, 0x12, 0x1200},
		{12, false, 0x12, 0x000012ff},
		{13, false, 0x12, 0x0012ffff},
		{14, false, 0x12, 0x12},
		{14, true, 0xaa, 0xff00ff00ff00ff00},
		{15, false, 0x70, 0x3f800000},
		{0, true, 0x12, 0xffffffed},
	} {
		word := encodeARMRawNEONModifiedImmediate(test.cmode, test.invert, false, 0, test.imm8)
		form, ok := decodeARMRawNEONModifiedImmediate(word)
		if !ok {
			t.Fatalf("encoding %#08x rejected", word)
		}
		if got := expandARMRawNEONModifiedImmediate(form); got != test.want {
			t.Fatalf("encoding %#08x expanded to %#x, want %#x", word, got, test.want)
		}
	}
}

func TestARMRawNEONModifiedImmediateRejectsReservedForms(t *testing.T) {
	for _, word := range []uint32{
		encodeARMRawNEONModifiedImmediate(1, false, false, 0, 0x12),
		encodeARMRawNEONModifiedImmediate(3, true, false, 0, 0x12),
		encodeARMRawNEONModifiedImmediate(15, true, false, 0, 0x12),
		encodeARMRawNEONModifiedImmediate(6, false, true, 1, 0x12),
	} {
		if _, ok := decodeARMRawNEONModifiedImmediate(word); ok {
			t.Fatalf("accepted reserved VMOV/VMVN immediate encoding %#08x", word)
		}
	}
}
