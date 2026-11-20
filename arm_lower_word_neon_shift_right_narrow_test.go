package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARMRawNEONShiftRightNarrow(sourceBits, shift, destination, source int) uint32 {
	imm6 := sourceBits - shift
	return uint32(0xf2800810 | imm6<<16 | (destination&15)<<12 |
		(destination/16)<<22 | source&15 | (source/16)<<5)
}

func TestARMRawNEONShiftRightNarrowLLVM22Forms(t *testing.T) {
	for _, test := range []struct {
		word        uint32
		sourceBits  int
		shift       int
		destination int
		source      int
	}{
		{0xf28f0812, 16, 1, 0, 2},
		{0xf2880812, 16, 8, 0, 2},
		{0xf29f0812, 32, 1, 0, 2},
		{0xf2900812, 32, 16, 0, 2},
		{0xf2bf0812, 64, 1, 0, 2},
		{0xf2e6e832, 64, 26, 30, 18},
		{0xf2a00812, 64, 32, 0, 2},
	} {
		got, ok := decodeARMRawNEONShiftRightNarrow(test.word)
		if !ok || got.sourceBits != test.sourceBits || got.shift != test.shift ||
			got.destination != test.destination || got.source != test.source {
			t.Fatalf("LLVM 22 encoding %#08x decoded as %+v, ok=%v", test.word, got, ok)
		}
		if encoded := encodeARMRawNEONShiftRightNarrow(
			test.sourceBits, test.shift, test.destination, test.source,
		); encoded != test.word {
			t.Fatalf("encoded %+v as %#08x, want %#08x", test, encoded, test.word)
		}
	}
}

func TestARMRawNEONShiftRightNarrowAllFields(t *testing.T) {
	count := 0
	for _, sourceBits := range []int{16, 32, 64} {
		for _, shift := range []int{1, sourceBits / 4, sourceBits / 2} {
			for destination := 0; destination < 32; destination++ {
				for source := 0; source < 32; source += 2 {
					word := encodeARMRawNEONShiftRightNarrow(sourceBits, shift, destination, source)
					got, ok := decodeARMRawNEONShiftRightNarrow(word)
					if !ok || got.sourceBits != sourceBits || got.shift != shift ||
						got.destination != destination || got.source != source {
						t.Fatalf("encoding %#08x decoded as %+v, ok=%v", word, got, ok)
					}
					count++
				}
			}
		}
	}
	if count != 4608 {
		t.Fatalf("covered %d VSHRN forms, want 4608", count)
	}
}

func TestTranslateARMRawNEONShiftRightNarrowAllFormatsLLVM22(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawShiftNarrow(SB), $0-0\n")
	for _, sourceBits := range []int{16, 32, 64} {
		for _, shift := range []int{1, sourceBits / 2} {
			word := encodeARMRawNEONShiftRightNarrow(sourceBits, shift, 16, 18)
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
		Sigs: map[string]FuncSig{"rawShiftNarrow": {Name: "rawShiftNarrow", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"lshr <8 x i16>", "trunc <8 x i16>",
		"lshr <4 x i32>", "trunc <4 x i32>",
		"lshr <2 x i64>", "trunc <2 x i64>",
	} {
		if !strings.Contains(ir, fragment) {
			t.Fatalf("raw VSHRN omitted %q:\n%s", fragment, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, triple, "arm-raw-neon-vshrn.ll", "arm-raw-neon-vshrn.o", ir)
}

func TestARMRawNEONShiftRightNarrowRejectsReservedFields(t *testing.T) {
	base := encodeARMRawNEONShiftRightNarrow(64, 26, 0, 18)
	for _, word := range []uint32{
		base | 1,
		base ^ 1<<8,
		base | 1<<7,
		0xf2800810,
	} {
		if _, ok := decodeARMRawNEONShiftRightNarrow(word); ok {
			t.Fatalf("accepted reserved VSHRN encoding %#08x", word)
		}
	}
}
