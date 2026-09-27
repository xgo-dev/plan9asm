package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARMRawNEONStructureFourMultiple(load bool, elementBits, first, stride, base, offset, alignment int) uint32 {
	word := uint32(0xf4000000 | base<<16 | (first&15)<<12 | (first/16)<<22 | offset)
	if load {
		word |= 1 << 21
	}
	if stride == 2 {
		word |= 1 << 8
	}
	word |= uint32(map[int]int{8: 0, 16: 1, 32: 2}[elementBits]) << 6
	word |= uint32(map[int]int{0: 0, 8: 1, 16: 2, 32: 3}[alignment]) << 4
	return word
}

func TestARMRawNEONStructureFourMultipleLLVM22Forms(t *testing.T) {
	for _, test := range []struct {
		word        uint32
		load        bool
		elementBits int
		first       int
		stride      int
		base        int
		offset      int
		alignment   int
	}{
		{0xf421000f, true, 8, 0, 1, 1, 15, 0},
		{0xf421010f, true, 8, 0, 2, 1, 15, 0},
		{0xf421004f, true, 16, 0, 1, 1, 15, 0},
		{0xf421014f, true, 16, 0, 2, 1, 15, 0},
		{0xf421008f, true, 32, 0, 1, 1, 15, 0},
		{0xf421018f, true, 32, 0, 2, 1, 15, 0},
		{0xf461418f, true, 32, 20, 2, 1, 15, 0},
		{0xf401008d, false, 32, 0, 1, 1, 13, 0},
		{0xf401018d, false, 32, 0, 2, 1, 13, 0},
		{0xf42100bd, true, 32, 0, 1, 1, 13, 32},
	} {
		got, ok := decodeARMRawNEONStructureFourMultiple(test.word)
		if !ok || got.load != test.load || got.elementBits != test.elementBits ||
			got.first != test.first || got.stride != test.stride ||
			got.base != test.base || got.offset != test.offset || got.alignment != test.alignment {
			t.Fatalf("LLVM 22 encoding %#08x decoded as %+v, ok=%v", test.word, got, ok)
		}
		if encoded := encodeARMRawNEONStructureFourMultiple(
			test.load, test.elementBits, test.first, test.stride,
			test.base, test.offset, test.alignment,
		); encoded != test.word {
			t.Fatalf("encoded %+v as %#08x, want %#08x", test, encoded, test.word)
		}
	}
}

func TestARMRawNEONStructureFourMultipleAllFields(t *testing.T) {
	count := 0
	for _, load := range []bool{false, true} {
		for _, elementBits := range []int{8, 16, 32} {
			for _, stride := range []int{1, 2} {
				for _, alignment := range []int{0, 8, 16, 32} {
					for first := 0; first+3*stride < 32; first++ {
						for _, offset := range []int{0, 13, 15} {
							word := encodeARMRawNEONStructureFourMultiple(
								load, elementBits, first, stride, 1, offset, alignment,
							)
							got, ok := decodeARMRawNEONStructureFourMultiple(word)
							if !ok || got.load != load || got.elementBits != elementBits ||
								got.first != first || got.stride != stride ||
								got.base != 1 || got.offset != offset || got.alignment != alignment {
								t.Fatalf("encoding %#08x decoded as %+v, ok=%v", word, got, ok)
							}
							count++
						}
					}
				}
			}
		}
	}
	if count != 3960 {
		t.Fatalf("covered %d VLD4/VST4 multiple forms, want 3960", count)
	}
}

func TestTranslateARMRawNEONStructureFourMultipleLLVM22(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawStructureFourMultiple(SB), $0-0\n")
	for _, load := range []bool{false, true} {
		for _, elementBits := range []int{8, 16, 32} {
			for _, stride := range []int{1, 2} {
				word := encodeARMRawNEONStructureFourMultiple(
					load, elementBits, 16, stride, 1, 13, 0,
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
		Sigs: map[string]FuncSig{"rawStructureFourMultiple": {Name: "rawStructureFourMultiple", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"load i8, ptr", "store i8", "load i16, ptr", "store i16",
		"load i32, ptr", "store i32", "insertelement", "extractelement",
	} {
		if !strings.Contains(ir, fragment) {
			t.Fatalf("raw VLD4/VST4 multiple omitted %q:\n%s", fragment, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, triple, "arm-raw-neon-structure-four-multiple.ll", "arm-raw-neon-structure-four-multiple.o", ir)
}
