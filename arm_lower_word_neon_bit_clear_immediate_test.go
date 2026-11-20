package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARMRawNEONBitClearImmediate(quad bool, elementBits, shift, destination, imm8 int) uint32 {
	cmode := 1 + shift/4
	if elementBits == 16 {
		cmode = 9 + shift/4
	}
	word := uint32(0xf2800030 | (imm8>>7)<<24 | ((imm8>>4)&7)<<16 |
		(destination&15)<<12 | (destination/16)<<22 | cmode<<8 | imm8&15)
	if quad {
		word |= 1 << 6
	}
	return word
}

func TestARMRawNEONBitClearImmediateLLVM22Forms(t *testing.T) {
	for _, test := range []struct {
		word        uint32
		quad        bool
		elementBits int
		shift       int
		destination int
		imm8        int
	}{
		{0xf387093c, false, 16, 0, 0, 0xfc},
		{0xf3870b7c, true, 16, 8, 0, 0xfc},
		{0xf387013c, false, 32, 0, 0, 0xfc},
		{0xf387037c, true, 32, 8, 0, 0xfc},
		{0xf387053c, false, 32, 16, 0, 0xfc},
		{0xf3c7073c, false, 32, 24, 16, 0xfc},
	} {
		got, ok := decodeARMRawNEONBitClearImmediate(test.word)
		if !ok || got.quad != test.quad || got.elementBits != test.elementBits ||
			got.shift != test.shift || got.destination != test.destination || got.imm8 != test.imm8 {
			t.Fatalf("LLVM 22 encoding %#08x decoded as %+v, ok=%v", test.word, got, ok)
		}
		if encoded := encodeARMRawNEONBitClearImmediate(
			test.quad, test.elementBits, test.shift, test.destination, test.imm8,
		); encoded != test.word {
			t.Fatalf("encoded %+v as %#08x, want %#08x", test, encoded, test.word)
		}
	}
}

func TestARMRawNEONBitClearImmediateAllFields(t *testing.T) {
	count := 0
	for _, elementBits := range []int{16, 32} {
		for shift := 0; shift < elementBits; shift += 8 {
			for _, quad := range []bool{false, true} {
				step := 1
				if quad {
					step = 2
				}
				for destination := 0; destination < 32; destination += step {
					for imm8 := 0; imm8 < 256; imm8++ {
						word := encodeARMRawNEONBitClearImmediate(
							quad, elementBits, shift, destination, imm8,
						)
						got, ok := decodeARMRawNEONBitClearImmediate(word)
						if !ok || got.quad != quad || got.elementBits != elementBits ||
							got.shift != shift || got.destination != destination || got.imm8 != imm8 {
							t.Fatalf("encoding %#08x decoded as %+v, ok=%v", word, got, ok)
						}
						count++
					}
				}
			}
		}
	}
	if count != 73728 {
		t.Fatalf("covered %d VBIC immediate forms, want 73728", count)
	}
}

func TestTranslateARMRawNEONBitClearImmediateAllFormatsLLVM22(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawBIC(SB), $0-0\n")
	for _, elementBits := range []int{16, 32} {
		for shift := 0; shift < elementBits; shift += 8 {
			for _, quad := range []bool{false, true} {
				word := encodeARMRawNEONBitClearImmediate(quad, elementBits, shift, 16, 0xfc)
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
		Sigs: map[string]FuncSig{"rawBIC": {Name: "rawBIC", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"and <4 x i16>", "and <8 x i16>",
		"and <2 x i32>", "and <4 x i32>",
	} {
		if !strings.Contains(ir, fragment) {
			t.Fatalf("raw VBIC immediate omitted %q:\n%s", fragment, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, triple, "arm-raw-neon-vbic-imm.ll", "arm-raw-neon-vbic-imm.o", ir)
}

func TestARMRawNEONBitClearImmediateRejectsReservedFields(t *testing.T) {
	base := encodeARMRawNEONBitClearImmediate(true, 32, 24, 0, 0xfc)
	for _, word := range []uint32{
		base | 1<<12,
		base ^ 1<<5,
		base &^ (7 << 8),
	} {
		if _, ok := decodeARMRawNEONBitClearImmediate(word); ok {
			t.Fatalf("accepted reserved VBIC immediate encoding %#08x", word)
		}
	}
}
