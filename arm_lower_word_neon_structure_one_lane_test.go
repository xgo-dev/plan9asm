package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARMRawNEONStructureOneLane(load bool, elementBits, lane, register, base, offset, alignment int) uint32 {
	word := uint32(0xf4800000 | base<<16 | (register&15)<<12 | (register/16)<<22 | offset)
	if load {
		word |= 1 << 21
	}
	switch elementBits {
	case 8:
		word |= uint32(lane) << 5
	case 16:
		word |= 4 << 8
		word |= uint32(lane) << 6
		if alignment == 2 {
			word |= 1 << 4
		}
	case 32:
		word |= 8 << 8
		word |= uint32(lane) << 7
		if alignment == 4 {
			word |= 3 << 4
		}
	}
	return word
}

func TestARMRawNEONStructureOneLaneLLVM22Forms(t *testing.T) {
	for _, test := range []struct {
		word        uint32
		load        bool
		elementBits int
		lane        int
		register    int
		base        int
		offset      int
		alignment   int
	}{
		{0xf486000f, false, 8, 0, 0, 6, 15, 0},
		{0xf48600ed, false, 8, 7, 0, 6, 13, 0},
		{0xf4a6000f, true, 8, 0, 0, 6, 15, 0},
		{0xf486040f, false, 16, 0, 0, 6, 15, 0},
		{0xf48604cd, false, 16, 3, 0, 6, 13, 0},
		{0xf486883f, false, 32, 0, 8, 6, 15, 4},
		{0xf48788bf, false, 32, 1, 8, 7, 15, 4},
		{0xf4a6883f, true, 32, 0, 8, 6, 15, 4},
	} {
		got, ok := decodeARMRawNEONStructureOneLane(test.word)
		if !ok || got.load != test.load || got.elementBits != test.elementBits ||
			got.lane != test.lane || got.first != test.register ||
			got.base != test.base || got.offset != test.offset || got.alignment != test.alignment {
			t.Fatalf("LLVM 22 encoding %#08x decoded as %+v, ok=%v", test.word, got, ok)
		}
		if encoded := encodeARMRawNEONStructureOneLane(
			test.load, test.elementBits, test.lane, test.register,
			test.base, test.offset, test.alignment,
		); encoded != test.word {
			t.Fatalf("encoded %+v as %#08x, want %#08x", test, encoded, test.word)
		}
	}
}

func TestARMRawNEONStructureOneLaneAllFields(t *testing.T) {
	count := 0
	for _, load := range []bool{false, true} {
		for _, elementBits := range []int{8, 16, 32} {
			alignments := []int{0}
			if elementBits == 16 {
				alignments = []int{0, 2}
			} else if elementBits == 32 {
				alignments = []int{0, 4}
			}
			for _, alignment := range alignments {
				for lane := 0; lane < 64/elementBits; lane++ {
					for register := 0; register < 32; register++ {
						for _, offset := range []int{0, 13, 15} {
							word := encodeARMRawNEONStructureOneLane(
								load, elementBits, lane, register, 6, offset, alignment,
							)
							got, ok := decodeARMRawNEONStructureOneLane(word)
							if !ok || got.load != load || got.elementBits != elementBits ||
								got.lane != lane || got.first != register || got.base != 6 ||
								got.offset != offset || got.alignment != alignment {
								t.Fatalf("encoding %#08x decoded as %+v, ok=%v", word, got, ok)
							}
							count++
						}
					}
				}
			}
		}
	}
	if count != 3840 {
		t.Fatalf("covered %d VLD1/VST1 lane forms, want 3840", count)
	}
}

func TestTranslateARMRawNEONStructureOneLaneLLVM22(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawStructureOneLane(SB), $0-0\n")
	for _, load := range []bool{false, true} {
		for _, elementBits := range []int{8, 16, 32} {
			word := encodeARMRawNEONStructureOneLane(load, elementBits, 0, 16, 6, 13, 0)
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
		Sigs: map[string]FuncSig{"rawStructureOneLane": {Name: "rawStructureOneLane", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"load i8, ptr", "store i8", "load i16, ptr", "store i16",
		"load i32, ptr", "store i32", "insertelement", "extractelement",
	} {
		if !strings.Contains(ir, fragment) {
			t.Fatalf("raw VLD1/VST1 lane omitted %q:\n%s", fragment, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, triple, "arm-raw-neon-structure-one-lane.ll", "arm-raw-neon-structure-one-lane.o", ir)
}

func TestARMRawNEONStructureOneLaneRejectsReservedAndUnsafe(t *testing.T) {
	base := encodeARMRawNEONStructureOneLane(false, 32, 0, 0, 6, 13, 0)
	for _, word := range []uint32{
		base | 1<<4,
		base | 1<<5,
		base | 1<<6,
		base ^ 4<<8,
	} {
		if _, ok := decodeARMRawNEONStructureOneLane(word); ok {
			t.Fatalf("accepted reserved VLD1/VST1 lane encoding %#08x", word)
		}
	}
	word := encodeARMRawNEONStructureOneLane(true, 32, 0, 0, 15, 13, 0)
	file, err := Parse(ArchARM, fmt.Sprintf("TEXT badStructureOne(SB), $0-0\n\tWORD $%#08x\n\tRET\n", word))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{
		Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf",
		Sigs: map[string]FuncSig{"badStructureOne": {Name: "badStructureOne", Ret: Void}},
	}); err == nil {
		t.Fatal("accepted PC as VLD1/VST1 lane base")
	}
}
