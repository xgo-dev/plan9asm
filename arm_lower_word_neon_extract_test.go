package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARMRawNEONExtract(quad bool, destination, lhs, rhs, offset int) uint32 {
	word := uint32(0xf2b00000 | (destination&15)<<12 | (destination/16)<<22 |
		(lhs&15)<<16 | (lhs/16)<<7 | rhs&15 | (rhs/16)<<5 | offset<<8)
	if quad {
		word |= 1 << 6
	}
	return word
}

func TestARMRawNEONExtractLLVM22Forms(t *testing.T) {
	for _, test := range []struct {
		word        uint32
		quad        bool
		destination int
		lhs         int
		rhs         int
		offset      int
	}{
		{0xf2b10002, false, 0, 1, 2, 0},
		{0xf2b10702, false, 0, 1, 2, 7},
		{0xf2b20044, true, 0, 2, 4, 0},
		{0xf2b20f44, true, 0, 2, 4, 15},
		{0xf2b44844, true, 4, 4, 4, 8},
		{0xf2f0efec, true, 30, 16, 28, 15},
	} {
		got, ok := decodeARMRawNEONExtract(test.word)
		if !ok || got.quad != test.quad || got.destination != test.destination ||
			got.lhs != test.lhs || got.rhs != test.rhs || got.offset != test.offset {
			t.Fatalf("LLVM 22 encoding %#08x decoded as %+v, ok=%v", test.word, got, ok)
		}
		if encoded := encodeARMRawNEONExtract(
			test.quad, test.destination, test.lhs, test.rhs, test.offset,
		); encoded != test.word {
			t.Fatalf("encoded %+v as %#08x, want %#08x", test, encoded, test.word)
		}
	}
}

func TestARMRawNEONExtractAllRegisterFields(t *testing.T) {
	count := 0
	for _, quad := range []bool{false, true} {
		step, offsets := 1, 8
		if quad {
			step, offsets = 2, 16
		}
		for destination := 0; destination < 32; destination += step {
			for lhs := 0; lhs < 32; lhs += step {
				for rhs := 0; rhs < 32; rhs += step {
					for offset := 0; offset < offsets; offset++ {
						word := encodeARMRawNEONExtract(quad, destination, lhs, rhs, offset)
						got, ok := decodeARMRawNEONExtract(word)
						if !ok || got.quad != quad || got.destination != destination ||
							got.lhs != lhs || got.rhs != rhs || got.offset != offset {
							t.Fatalf("encoding %#08x decoded as %+v, ok=%v", word, got, ok)
						}
						count++
					}
				}
			}
		}
	}
	if count != 327680 {
		t.Fatalf("covered %d VEXT forms, want 327680", count)
	}
}

func TestTranslateARMRawNEONExtractAllFormatsLLVM22(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawExtract(SB), $0-0\n")
	for _, quad := range []bool{false, true} {
		maxOffset := 7
		if quad {
			maxOffset = 15
		}
		for _, offset := range []int{0, maxOffset / 2, maxOffset} {
			word := encodeARMRawNEONExtract(quad, 4, 2, 6, offset)
			fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
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
		Sigs: map[string]FuncSig{"rawExtract": {Name: "rawExtract", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"shufflevector <8 x i8>", "shufflevector <16 x i8>"} {
		if !strings.Contains(ir, fragment) {
			t.Fatalf("raw VEXT omitted %q:\n%s", fragment, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, triple, "arm-raw-neon-vext.ll", "arm-raw-neon-vext.o", ir)
}

func TestARMRawNEONExtractRejectsReservedFields(t *testing.T) {
	base := encodeARMRawNEONExtract(true, 0, 2, 4, 8)
	for _, word := range []uint32{
		base | 1<<12,
		base | 1<<16,
		base | 1,
		base ^ 1<<24,
		encodeARMRawNEONExtract(false, 0, 1, 2, 8),
	} {
		if _, ok := decodeARMRawNEONExtract(word); ok {
			t.Fatalf("accepted reserved VEXT encoding %#08x", word)
		}
	}
}
