package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARMRawNEONShiftImmediate(elementBits, shift, destination, source int, quad bool) uint32 {
	imm7 := elementBits + shift
	word := uint32(0xf2800510 | (imm7&0x3f)<<16 | (imm7>>6)<<7 |
		(destination&15)<<12 | (destination/16)<<22 | source&15 | (source/16)<<5)
	if quad {
		word |= 1 << 6
	}
	return word
}

func TestTranslateARMRawNEONShiftImmediateWireGuardRegression(t *testing.T) {
	const source = `TEXT rawNEONShift(SB), $0-0
	WORD $0xf2e1a538
	RET
`
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch:       "arm",
		TargetTriple: "armv7-unknown-linux-gnueabihf",
		Sigs:         map[string]FuncSig{"rawNEONShift": {Name: "rawNEONShift", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "shl <2 x i32>") {
		t.Fatalf("raw ARM VSHL.I32 omitted per-lane shift:\n%s", ir)
	}
}

func TestARMRawNEONShiftImmediateLLVM22Forms(t *testing.T) {
	for _, test := range []struct {
		word        uint32
		elementBits int
		shift       int
		destination int
		source      int
		quad        bool
	}{
		{0xf28b1512, 8, 3, 1, 2, false},
		{0xf2951512, 16, 5, 1, 2, false},
		{0xf2a11512, 32, 1, 1, 2, false},
		{0xf2a51592, 64, 37, 1, 2, false},
		{0xf28f6558, 8, 7, 6, 8, true},
		{0xf29f6558, 16, 15, 6, 8, true},
		{0xf2bf6558, 32, 31, 6, 8, true},
		{0xf2bf65d8, 64, 63, 6, 8, true},
		{0xf2e1a538, 32, 1, 26, 24, false},
	} {
		got, ok := decodeARMRawNEONShiftImmediate(test.word)
		if !ok || got.elementBits != test.elementBits || got.shift != test.shift ||
			got.destination != test.destination || got.source != test.source || got.quad != test.quad {
			t.Fatalf("LLVM 22 encoding %#08x decoded as %+v, ok=%v", test.word, got, ok)
		}
		if encoded := encodeARMRawNEONShiftImmediate(
			test.elementBits, test.shift, test.destination, test.source, test.quad,
		); encoded != test.word {
			t.Fatalf("form %+v encoded as %#08x, want %#08x", test, encoded, test.word)
		}
	}
}

func TestARMRawNEONShiftImmediateAllFields(t *testing.T) {
	count := 0
	for _, elementBits := range []int{8, 16, 32, 64} {
		for _, quad := range []bool{false, true} {
			step := 1
			if quad {
				step = 2
			}
			for _, shift := range []int{0, elementBits / 2, elementBits - 1} {
				for destination := 0; destination < 32; destination += step {
					for source := 0; source < 32; source += step {
						word := encodeARMRawNEONShiftImmediate(
							elementBits, shift, destination, source, quad,
						)
						got, ok := decodeARMRawNEONShiftImmediate(word)
						if !ok || got.elementBits != elementBits || got.shift != shift ||
							got.quad != quad || got.destination != destination || got.source != source {
							t.Fatalf("encoding %#08x decoded as %+v, ok=%v", word, got, ok)
						}
						count++
					}
				}
			}
		}
	}
	if count != 15360 {
		t.Fatalf("covered %d VSHL immediate encodings, want 15360", count)
	}
}

func TestTranslateARMRawNEONShiftImmediateAllFormatsLLVM22(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawNEONShiftFamily(SB), $0-0\n")
	for _, elementBits := range []int{8, 16, 32, 64} {
		for _, quad := range []bool{false, true} {
			word := encodeARMRawNEONShiftImmediate(elementBits, elementBits-1, 0, 2, quad)
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
		Goarch:       "arm",
		TargetTriple: triple,
		Sigs:         map[string]FuncSig{"rawNEONShiftFamily": {Name: "rawNEONShiftFamily", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"shl <8 x i8>", "shl <16 x i8>", "shl <4 x i16>", "shl <8 x i16>",
		"shl <2 x i32>", "shl <4 x i32>", "shl <1 x i64>", "shl <2 x i64>",
	} {
		if !strings.Contains(ir, fragment) {
			t.Fatalf("VSHL immediate family IR omitted %q:\n%s", fragment, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, triple, "arm-neon-vshl-immediate.ll", "arm-neon-vshl-immediate.o", ir)
}

func TestARMRawNEONShiftImmediateRejectsReservedFields(t *testing.T) {
	base := encodeARMRawNEONShiftImmediate(16, 5, 0, 2, false)
	for _, word := range []uint32{
		0xf2800510 | 7<<16,
		base &^ (1 << 4),
		base | 1<<24,
		encodeARMRawNEONShiftImmediate(16, 5, 1, 2, true),
		encodeARMRawNEONShiftImmediate(16, 5, 0, 3, true),
	} {
		if _, ok := decodeARMRawNEONShiftImmediate(word); ok {
			t.Fatalf("accepted reserved VSHL immediate encoding %#08x", word)
		}
	}
}
