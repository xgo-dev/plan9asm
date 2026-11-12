package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARMRawNEONStructureFourLane(load bool, elementBits, lane, first, stride, base, offset, alignment int) uint32 {
	word := uint32(0xf4800000 | base<<16 | (first&15)<<12 | (first/16)<<22 | offset)
	if load {
		word |= 1 << 21
	}
	switch elementBits {
	case 8:
		word |= 3 << 8
		word |= uint32(lane) << 5
		if alignment == 4 {
			word |= 1 << 4
		}
	case 16:
		word |= 7 << 8
		word |= uint32(lane) << 6
		if stride == 2 {
			word |= 1 << 5
		}
		if alignment == 8 {
			word |= 1 << 4
		}
	case 32:
		word |= 11 << 8
		word |= uint32(lane) << 7
		if stride == 2 {
			word |= 1 << 6
		}
		switch alignment {
		case 8:
			word |= 1 << 4
		case 16:
			word |= 2 << 4
		}
	}
	return word
}

func TestARMRawNEONStructureFourLaneLLVM22Forms(t *testing.T) {
	for _, test := range []struct {
		word        uint32
		load        bool
		elementBits int
		lane        int
		first       int
		stride      int
		base        int
		offset      int
		alignment   int
	}{
		{0xf486030f, false, 8, 0, 0, 1, 6, 15, 0},
		{0xf48603ed, false, 8, 7, 0, 1, 6, 13, 0},
		{0xf4a6030f, true, 8, 0, 0, 1, 6, 15, 0},
		{0xf486070f, false, 16, 0, 0, 1, 6, 15, 0},
		{0xf48607cd, false, 16, 3, 0, 1, 6, 13, 0},
		{0xf486072d, false, 16, 0, 0, 2, 6, 13, 0},
		{0xf4860b0d, false, 32, 0, 0, 1, 6, 13, 0},
		{0xf4870b8d, false, 32, 1, 0, 1, 7, 13, 0},
		{0xf4a60b0d, true, 32, 0, 0, 1, 6, 13, 0},
		{0xf4860b4d, false, 32, 0, 0, 2, 6, 13, 0},
		{0xf4c6cb8d, false, 32, 1, 28, 1, 6, 13, 0},
	} {
		got, ok := decodeARMRawNEONStructureFourLane(test.word)
		if !ok || got.load != test.load || got.elementBits != test.elementBits ||
			got.lane != test.lane || got.first != test.first || got.stride != test.stride ||
			got.base != test.base || got.offset != test.offset || got.alignment != test.alignment {
			t.Fatalf("LLVM 22 encoding %#08x decoded as %+v, ok=%v", test.word, got, ok)
		}
		if encoded := encodeARMRawNEONStructureFourLane(
			test.load, test.elementBits, test.lane, test.first,
			test.stride, test.base, test.offset, test.alignment,
		); encoded != test.word {
			t.Fatalf("encoded %+v as %#08x, want %#08x", test, encoded, test.word)
		}
	}
}

func TestARMRawNEONStructureFourLaneAllFields(t *testing.T) {
	count := 0
	for _, load := range []bool{false, true} {
		for _, elementBits := range []int{8, 16, 32} {
			strides := []int{1, 2}
			alignments := []int{0, 8}
			if elementBits == 8 {
				strides = []int{1}
				alignments = []int{0, 4}
			} else if elementBits == 32 {
				alignments = []int{0, 8, 16}
			}
			for _, stride := range strides {
				for _, alignment := range alignments {
					for lane := 0; lane < 64/elementBits; lane++ {
						for first := 0; first+3*stride < 32; first++ {
							word := encodeARMRawNEONStructureFourLane(
								load, elementBits, lane, first, stride, 6, 13, alignment,
							)
							got, ok := decodeARMRawNEONStructureFourLane(word)
							if !ok || got.load != load || got.elementBits != elementBits ||
								got.lane != lane || got.first != first || got.stride != stride ||
								got.base != 6 || got.offset != 13 || got.alignment != alignment {
								t.Fatalf("encoding %#08x decoded as %+v, ok=%v", word, got, ok)
							}
							count++
						}
					}
				}
			}
		}
	}
	if count == 0 {
		t.Fatal("covered no VLD4/VST4 lane forms")
	}
}

func TestTranslateARMRawNEONStructureFourLaneLLVM22(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawStructureFour(SB), $0-0\n")
	for _, load := range []bool{false, true} {
		for _, elementBits := range []int{8, 16, 32} {
			for _, stride := range []int{1, 2} {
				if elementBits == 8 && stride == 2 {
					continue
				}
				word := encodeARMRawNEONStructureFourLane(
					load, elementBits, 0, 0, stride, 6, 13, 0,
				)
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
		Sigs: map[string]FuncSig{"rawStructureFour": {Name: "rawStructureFour", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"load i8, ptr", "store i8", "load i16, ptr", "store i16",
		"load i32, ptr", "store i32", "insertelement", "extractelement",
	} {
		if !strings.Contains(ir, fragment) {
			t.Fatalf("raw VLD4/VST4 lane omitted %q:\n%s", fragment, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, triple, "arm-raw-neon-structure-four-lane.ll", "arm-raw-neon-structure-four-lane.o", ir)
}

func TestARMRawNEONStructureFourLaneRejectsReservedAndUnsafe(t *testing.T) {
	base := encodeARMRawNEONStructureFourLane(false, 32, 0, 0, 1, 6, 13, 0)
	for _, word := range []uint32{
		base | 3<<4,
		base &^ (15 << 8),
		encodeARMRawNEONStructureFourLane(false, 32, 0, 30, 1, 6, 13, 0),
		encodeARMRawNEONStructureFourLane(false, 16, 0, 26, 2, 6, 13, 0),
	} {
		if _, ok := decodeARMRawNEONStructureFourLane(word); ok {
			t.Fatalf("accepted reserved VLD4/VST4 lane encoding %#08x", word)
		}
	}
	word := encodeARMRawNEONStructureFourLane(true, 32, 0, 0, 1, 15, 13, 0)
	file, err := Parse(ArchARM, fmt.Sprintf("TEXT badStructureFour(SB), $0-0\n\tWORD $%#08x\n\tRET\n", word))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{
		Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf",
		Sigs: map[string]FuncSig{"badStructureFour": {Name: "badStructureFour", Ret: Void}},
	}); err == nil {
		t.Fatal("accepted PC as VLD4/VST4 lane base")
	}
}
