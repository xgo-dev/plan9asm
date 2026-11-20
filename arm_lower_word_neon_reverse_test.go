package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARMRawNEONReverse(blockBits, elementBits, destination, source int, quad bool) uint32 {
	word := uint32(0xf3b00000 | (destination&15)<<12 | (destination/16)<<22 |
		source&15 | (source/16)<<5)
	if quad {
		word |= 1 << 6
	}
	switch blockBits {
	case 16:
		word |= 1 << 8
	case 32:
		word |= 1 << 7
	}
	switch elementBits {
	case 16:
		word |= 1 << 18
	case 32:
		word |= 1 << 19
	}
	return word
}

func TestARMRawNEONReverseLLVM22Forms(t *testing.T) {
	for _, test := range []struct {
		word        uint32
		blockBits   int
		elementBits int
		destination int
		source      int
		quad        bool
	}{
		{0xf3b00101, 16, 8, 0, 1, false},
		{0xf3b00142, 16, 8, 0, 2, true},
		{0xf3b00081, 32, 8, 0, 1, false},
		{0xf3b460c6, 32, 16, 6, 6, true},
		{0xf3b00001, 64, 8, 0, 1, false},
		{0xf3b40001, 64, 16, 0, 1, false},
		{0xf3b80001, 64, 32, 0, 1, false},
		{0xf3f4e0e0, 32, 16, 30, 16, true},
	} {
		got, ok := decodeARMRawNEONReverse(test.word)
		if !ok || got.blockBits != test.blockBits || got.elementBits != test.elementBits ||
			got.destination != test.destination || got.source != test.source || got.quad != test.quad {
			t.Fatalf("LLVM 22 encoding %#08x decoded as %+v, ok=%v", test.word, got, ok)
		}
		if encoded := encodeARMRawNEONReverse(
			test.blockBits, test.elementBits, test.destination, test.source, test.quad,
		); encoded != test.word {
			t.Fatalf("encoded %+v as %#08x, want %#08x", test, encoded, test.word)
		}
	}
}

func TestARMRawNEONReverseAllRegisterFields(t *testing.T) {
	count := 0
	for _, blockBits := range []int{16, 32, 64} {
		for elementBits := 8; elementBits < blockBits; elementBits *= 2 {
			for _, quad := range []bool{false, true} {
				step := 1
				if quad {
					step = 2
				}
				for destination := 0; destination < 32; destination += step {
					for source := 0; source < 32; source += step {
						word := encodeARMRawNEONReverse(blockBits, elementBits, destination, source, quad)
						got, ok := decodeARMRawNEONReverse(word)
						if !ok || got.blockBits != blockBits || got.elementBits != elementBits ||
							got.destination != destination || got.source != source || got.quad != quad {
							t.Fatalf("encoding %#08x decoded as %+v, ok=%v", word, got, ok)
						}
						count++
					}
				}
			}
		}
	}
	if count != 7680 {
		t.Fatalf("covered %d VREV forms, want 7680", count)
	}
}

func TestTranslateARMRawNEONReverseAllFormatsLLVM22(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawReverse(SB), $0-0\n")
	for _, blockBits := range []int{16, 32, 64} {
		for elementBits := 8; elementBits < blockBits; elementBits *= 2 {
			for _, quad := range []bool{false, true} {
				word := encodeARMRawNEONReverse(blockBits, elementBits, 6, 8, quad)
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
		Sigs: map[string]FuncSig{"rawReverse": {Name: "rawReverse", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"shufflevector <8 x i8>", "shufflevector <16 x i8>",
		"shufflevector <4 x i16>", "shufflevector <8 x i16>",
		"shufflevector <2 x i32>", "shufflevector <4 x i32>",
	} {
		if !strings.Contains(ir, fragment) {
			t.Fatalf("raw VREV omitted %q:\n%s", fragment, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, triple, "arm-raw-neon-reverse.ll", "arm-raw-neon-reverse.o", ir)
}

func TestARMRawNEONReverseRejectsReservedFields(t *testing.T) {
	base := encodeARMRawNEONReverse(32, 16, 6, 8, true)
	for _, word := range []uint32{
		base | 1<<12,
		base | 1,
		base | 1<<8,
		encodeARMRawNEONReverse(16, 16, 0, 2, false),
		encodeARMRawNEONReverse(32, 32, 0, 2, false),
	} {
		if _, ok := decodeARMRawNEONReverse(word); ok {
			t.Fatalf("accepted reserved VREV encoding %#08x", word)
		}
	}
}
