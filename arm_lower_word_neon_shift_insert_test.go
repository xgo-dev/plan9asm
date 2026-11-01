package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARMRawNEONShiftInsert(left, quad bool, elementBits, shift, destination, source int) uint32 {
	imm7 := elementBits + shift
	word := uint32(0xf3800410)
	if left {
		word |= 1 << 8
	} else {
		imm7 = 2*elementBits - shift
	}
	word |= uint32((imm7&0x3f)<<16 | (imm7>>6)<<7 |
		(destination&15)<<12 | (destination/16)<<22 |
		source&15 | (source/16)<<5)
	if quad {
		word |= 1 << 6
	}
	return word
}

func TestARMRawNEONShiftInsertLLVM22Forms(t *testing.T) {
	for _, test := range []struct {
		word        uint32
		left        bool
		quad        bool
		elementBits int
		shift       int
		destination int
		source      int
	}{
		{0xf3880511, true, false, 8, 0, 0, 1},
		{0xf38f0511, true, false, 8, 7, 0, 1},
		{0xf3930552, true, true, 16, 3, 0, 2},
		{0xf3ac2578, true, true, 32, 12, 2, 24},
		{0xf3bf05d2, true, true, 64, 63, 0, 2},
		{0xf38f0411, false, false, 8, 1, 0, 1},
		{0xf3880411, false, false, 8, 8, 0, 1},
		{0xf39d0452, false, true, 16, 3, 0, 2},
		{0xf3b42478, false, true, 32, 12, 2, 24},
		{0xf38004d2, false, true, 64, 64, 0, 2},
	} {
		got, ok := decodeARMRawNEONShiftInsert(test.word)
		if !ok || got.left != test.left || got.quad != test.quad ||
			got.elementBits != test.elementBits || got.shift != test.shift ||
			got.destination != test.destination || got.source != test.source {
			t.Fatalf("LLVM 22 encoding %#08x decoded as %+v, ok=%v", test.word, got, ok)
		}
		if encoded := encodeARMRawNEONShiftInsert(
			test.left, test.quad, test.elementBits, test.shift,
			test.destination, test.source,
		); encoded != test.word {
			t.Fatalf("encoded %+v as %#08x, want %#08x", test, encoded, test.word)
		}
	}
}

func TestARMRawNEONShiftInsertAllFields(t *testing.T) {
	count := 0
	for _, left := range []bool{false, true} {
		for _, elementBits := range []int{8, 16, 32, 64} {
			shifts := []int{1, elementBits / 2, elementBits}
			if left {
				shifts = []int{0, elementBits / 2, elementBits - 1}
			}
			for _, shift := range shifts {
				for _, quad := range []bool{false, true} {
					step := 1
					if quad {
						step = 2
					}
					for destination := 0; destination < 32; destination += step {
						for source := 0; source < 32; source += step {
							word := encodeARMRawNEONShiftInsert(
								left, quad, elementBits, shift, destination, source,
							)
							got, ok := decodeARMRawNEONShiftInsert(word)
							if !ok || got.left != left || got.quad != quad ||
								got.elementBits != elementBits || got.shift != shift ||
								got.destination != destination || got.source != source {
								t.Fatalf("encoding %#08x decoded as %+v, ok=%v", word, got, ok)
							}
							count++
						}
					}
				}
			}
		}
	}
	if count != 30720 {
		t.Fatalf("covered %d VSLI/VSRI forms, want 30720", count)
	}
}

func TestTranslateARMRawNEONShiftInsertAllFormatsLLVM22(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawInsert(SB), $0-0\n")
	for _, left := range []bool{false, true} {
		for _, elementBits := range []int{8, 16, 32, 64} {
			for _, quad := range []bool{false, true} {
				shift := elementBits / 2
				word := encodeARMRawNEONShiftInsert(left, quad, elementBits, shift, 0, 2)
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
		Sigs: map[string]FuncSig{"rawInsert": {Name: "rawInsert", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"shl <8 x i8>", "lshr <8 x i8>",
		"shl <4 x i16>", "lshr <4 x i16>",
		"shl <2 x i32>", "lshr <2 x i32>",
		"shl <1 x i64>", "lshr <1 x i64>",
		"and <2 x i32>", "or <2 x i32>",
	} {
		if !strings.Contains(ir, fragment) {
			t.Fatalf("raw VSLI/VSRI omitted %q:\n%s", fragment, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, triple, "arm-raw-neon-shift-insert.ll", "arm-raw-neon-shift-insert.o", ir)
}

func TestARMRawNEONShiftInsertRejectsReservedFields(t *testing.T) {
	base := encodeARMRawNEONShiftInsert(true, true, 32, 12, 0, 2)
	for _, word := range []uint32{
		base | 1<<12,
		base | 1,
		base ^ 1<<9,
		0xf3800510,
	} {
		if _, ok := decodeARMRawNEONShiftInsert(word); ok {
			t.Fatalf("accepted reserved VSLI/VSRI encoding %#08x", word)
		}
	}
}
