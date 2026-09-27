package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARMRawNEONCoreLaneMove(toVector, unsigned bool, condition, elementBits, lane, vector, core int) uint32 {
	word := uint32(condition)<<28 | 0x0e000b10 | uint32(vector&15)<<16 |
		uint32(vector/16)<<7 | uint32(core)<<12
	if !toVector {
		word |= 1 << 20
		if unsigned {
			word |= 1 << 23
		}
	}
	switch elementBits {
	case 8:
		word |= 1 << 22
		word |= uint32(lane/4) << 21
		word |= uint32(lane>>1&1) << 6
		word |= uint32(lane&1) << 5
	case 16:
		word |= 1 << 5
		word |= uint32(lane/2) << 21
		word |= uint32(lane&1) << 6
	case 32:
		word |= uint32(lane) << 21
	}
	return word
}

func TestARMRawNEONCoreLaneMoveLLVM22Forms(t *testing.T) {
	for _, test := range []struct {
		word        uint32
		toVector    bool
		unsigned    bool
		elementBits int
		lane        int
		vector      int
		core        int
	}{
		{0xee401b10, true, false, 8, 0, 0, 1},
		{0xee601b70, true, false, 8, 7, 0, 1},
		{0xee001b30, true, false, 16, 0, 0, 1},
		{0xee201b70, true, false, 16, 3, 0, 1},
		{0xee001b10, true, false, 32, 0, 0, 1},
		{0xee201b10, true, false, 32, 1, 0, 1},
		{0xee005b90, true, false, 32, 0, 16, 5},
		{0xeed01b10, false, true, 8, 0, 0, 1},
		{0xee501b10, false, false, 8, 0, 0, 1},
		{0xee901b30, false, true, 16, 0, 0, 1},
		{0xee101b30, false, false, 16, 0, 0, 1},
		{0xee101b10, false, false, 32, 0, 0, 1},
		{0xee105b90, false, false, 32, 0, 16, 5},
	} {
		got, ok := decodeARMRawNEONCoreLaneMove(test.word)
		if !ok || got.toVector != test.toVector || got.unsigned != test.unsigned ||
			got.elementBits != test.elementBits || got.lane != test.lane ||
			got.vector != test.vector || got.core != test.core {
			t.Fatalf("LLVM 22 encoding %#08x decoded as %+v, ok=%v", test.word, got, ok)
		}
		if encoded := encodeARMRawNEONCoreLaneMove(
			test.toVector, test.unsigned, 14, test.elementBits,
			test.lane, test.vector, test.core,
		); encoded != test.word {
			t.Fatalf("encoded %+v as %#08x, want %#08x", test, encoded, test.word)
		}
	}
}

func TestARMRawNEONCoreLaneMoveAllFields(t *testing.T) {
	count := 0
	for _, toVector := range []bool{false, true} {
		for _, elementBits := range []int{8, 16, 32} {
			for _, unsigned := range []bool{false, true} {
				if toVector && unsigned || elementBits == 32 && unsigned {
					continue
				}
				for condition := 0; condition < 15; condition++ {
					for vector := 0; vector < 32; vector++ {
						for lane := 0; lane < 64/elementBits; lane++ {
							word := encodeARMRawNEONCoreLaneMove(
								toVector, unsigned, condition, elementBits, lane, vector, 5,
							)
							got, ok := decodeARMRawNEONCoreLaneMove(word)
							if !ok || got.toVector != toVector || got.unsigned != unsigned ||
								got.condition != armConditionName(condition) ||
								got.elementBits != elementBits || got.lane != lane ||
								got.vector != vector || got.core != 5 {
								t.Fatalf("encoding %#08x decoded as %+v, ok=%v", word, got, ok)
							}
							count++
						}
					}
				}
			}
		}
	}
	if count != 19200 {
		t.Fatalf("covered %d VMOV core/lane forms, want 19200", count)
	}
}

func TestTranslateARMRawNEONCoreLaneMoveAllFormatsLLVM22(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawCoreLane(SB), $0-0\n")
	for _, elementBits := range []int{8, 16, 32} {
		for _, toVector := range []bool{false, true} {
			unsignedValues := []bool{false}
			if !toVector && elementBits != 32 {
				unsignedValues = []bool{false, true}
			}
			for _, unsigned := range unsignedValues {
				word := encodeARMRawNEONCoreLaneMove(
					toVector, unsigned, 14, elementBits, 1, 16, 5,
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
		Sigs: map[string]FuncSig{"rawCoreLane": {Name: "rawCoreLane", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"insertelement <8 x i8>", "extractelement <8 x i8>",
		"insertelement <4 x i16>", "extractelement <4 x i16>",
		"insertelement <2 x i32>", "extractelement <2 x i32>",
		"sext i8", "zext i8",
	} {
		if !strings.Contains(ir, fragment) {
			t.Fatalf("raw VMOV core/lane omitted %q:\n%s", fragment, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, triple, "arm-raw-neon-core-lane.ll", "arm-raw-neon-core-lane.o", ir)
}

func TestARMRawNEONCoreLaneMoveRejectsReservedAndUnsafe(t *testing.T) {
	base := encodeARMRawNEONCoreLaneMove(true, false, 14, 32, 0, 16, 5)
	for _, word := range []uint32{
		base | 1<<23,
		base | 1<<6,
		base | 0xf0000000,
	} {
		if _, ok := decodeARMRawNEONCoreLaneMove(word); ok {
			t.Fatalf("accepted reserved VMOV core/lane encoding %#08x", word)
		}
	}
	word := encodeARMRawNEONCoreLaneMove(true, false, 14, 32, 0, 16, 15)
	file, err := Parse(ArchARM, fmt.Sprintf("TEXT badCoreLane(SB), $0-0\n\tWORD $%#08x\n\tRET\n", word))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{
		Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf",
		Sigs: map[string]FuncSig{"badCoreLane": {Name: "badCoreLane", Ret: Void}},
	}); err == nil {
		t.Fatal("accepted unsafe PC core/lane transfer")
	}
}
