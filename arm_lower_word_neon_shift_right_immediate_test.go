package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARMRawNEONShiftRightImmediate(unsigned, quad bool, elementBits, shift, destination, source int) uint32 {
	imm7 := 2*elementBits - shift
	word := uint32(0xf2800010 | (imm7&0x3f)<<16 | (imm7>>6)<<7 |
		(destination&15)<<12 | (destination/16)<<22 |
		source&15 | (source/16)<<5)
	if unsigned {
		word |= 1 << 24
	}
	if quad {
		word |= 1 << 6
	}
	return word
}

func TestARMRawNEONShiftRightImmediateLLVM22Forms(t *testing.T) {
	for _, test := range []struct {
		word        uint32
		unsigned    bool
		quad        bool
		elementBits int
		shift       int
		destination int
		source      int
	}{
		{0xf28f0011, false, false, 8, 1, 0, 1},
		{0xf29b0011, false, false, 16, 5, 0, 1},
		{0xf2ac0011, false, false, 32, 20, 0, 1},
		{0xf2a60091, false, false, 64, 26, 0, 1},
		{0xf38f0011, true, false, 8, 1, 0, 1},
		{0xf39b0011, true, false, 16, 5, 0, 1},
		{0xf3ac2078, true, true, 32, 20, 2, 24},
		{0xf3e6e0f0, true, true, 64, 26, 30, 16},
		{0xf3a00011, true, false, 32, 32, 0, 1},
		{0xf3800091, true, false, 64, 64, 0, 1},
		{0xf3880052, true, true, 8, 8, 0, 2},
		{0xf2a00052, false, true, 32, 32, 0, 2},
	} {
		got, ok := decodeARMRawNEONShiftRightImmediate(test.word)
		if !ok || got.unsigned != test.unsigned || got.quad != test.quad ||
			got.elementBits != test.elementBits || got.shift != test.shift ||
			got.destination != test.destination || got.source != test.source {
			t.Fatalf("LLVM 22 encoding %#08x decoded as %+v, ok=%v", test.word, got, ok)
		}
		if encoded := encodeARMRawNEONShiftRightImmediate(
			test.unsigned, test.quad, test.elementBits, test.shift,
			test.destination, test.source,
		); encoded != test.word {
			t.Fatalf("encoded %+v as %#08x, want %#08x", test, encoded, test.word)
		}
	}
}

func TestARMRawNEONShiftRightImmediateAllFields(t *testing.T) {
	count := 0
	for _, unsigned := range []bool{false, true} {
		for _, elementBits := range []int{8, 16, 32, 64} {
			for _, shift := range []int{1, elementBits / 2, elementBits} {
				for _, quad := range []bool{false, true} {
					step := 1
					if quad {
						step = 2
					}
					for destination := 0; destination < 32; destination += step {
						for source := 0; source < 32; source += step {
							word := encodeARMRawNEONShiftRightImmediate(
								unsigned, quad, elementBits, shift, destination, source,
							)
							got, ok := decodeARMRawNEONShiftRightImmediate(word)
							if !ok || got.unsigned != unsigned || got.quad != quad ||
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
		t.Fatalf("covered %d VSHR forms, want 30720", count)
	}
}

func TestTranslateARMRawNEONShiftRightImmediateAllFormatsLLVM22(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawVSHR(SB), $0-0\n")
	for _, unsigned := range []bool{false, true} {
		for _, elementBits := range []int{8, 16, 32, 64} {
			for _, shift := range []int{elementBits / 2, elementBits} {
				for _, quad := range []bool{false, true} {
					word := encodeARMRawNEONShiftRightImmediate(
						unsigned, quad, elementBits, shift, 0, 2,
					)
					fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
				}
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
		Sigs: map[string]FuncSig{"rawVSHR": {Name: "rawVSHR", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"ashr <8 x i8>", "lshr <8 x i8>",
		"ashr <4 x i16>", "lshr <4 x i16>",
		"ashr <2 x i32>", "lshr <2 x i32>",
		"ashr <1 x i64>", "lshr <1 x i64>",
		"zeroinitializer",
	} {
		if !strings.Contains(ir, fragment) {
			t.Fatalf("raw VSHR omitted %q:\n%s", fragment, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, triple, "arm-raw-neon-vshr.ll", "arm-raw-neon-vshr.o", ir)
}

func TestARMRawNEONShiftRightImmediateRejectsReservedFields(t *testing.T) {
	base := encodeARMRawNEONShiftRightImmediate(true, true, 32, 20, 0, 2)
	for _, word := range []uint32{
		base | 1<<12,
		base | 1,
		base ^ 1<<8,
		0xf2800010,
	} {
		if _, ok := decodeARMRawNEONShiftRightImmediate(word); ok {
			t.Fatalf("accepted reserved VSHR encoding %#08x", word)
		}
	}
}
