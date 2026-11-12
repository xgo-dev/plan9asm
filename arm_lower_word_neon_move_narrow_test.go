package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARMRawNEONMoveNarrow(sourceBits, destination, source int) uint32 {
	word := uint32(0xf3b20200 | (destination&15)<<12 | (destination/16)<<22 |
		source&15 | (source/16)<<5)
	switch sourceBits {
	case 32:
		word |= 1 << 18
	case 64:
		word |= 2 << 18
	}
	return word
}

func TestARMRawNEONMoveNarrowLLVM22Forms(t *testing.T) {
	for _, test := range []struct {
		word        uint32
		sourceBits  int
		destination int
		source      int
	}{
		{0xf3b20202, 16, 0, 2},
		{0xf3f2f22e, 16, 31, 30},
		{0xf3b60202, 32, 0, 2},
		{0xf3f6f22e, 32, 31, 30},
		{0xf3ba0202, 64, 0, 2},
		{0xf3fa0220, 64, 16, 16},
		{0xf3faf22e, 64, 31, 30},
	} {
		got, ok := decodeARMRawNEONMoveNarrow(test.word)
		if !ok || got.sourceBits != test.sourceBits ||
			got.destination != test.destination || got.source != test.source {
			t.Fatalf("LLVM 22 encoding %#08x decoded as %+v, ok=%v", test.word, got, ok)
		}
		if encoded := encodeARMRawNEONMoveNarrow(
			test.sourceBits, test.destination, test.source,
		); encoded != test.word {
			t.Fatalf("encoded %+v as %#08x, want %#08x", test, encoded, test.word)
		}
	}
}

func TestARMRawNEONMoveNarrowAllRegisterFields(t *testing.T) {
	count := 0
	for _, sourceBits := range []int{16, 32, 64} {
		for destination := 0; destination < 32; destination++ {
			for source := 0; source < 32; source += 2 {
				word := encodeARMRawNEONMoveNarrow(sourceBits, destination, source)
				got, ok := decodeARMRawNEONMoveNarrow(word)
				if !ok || got.sourceBits != sourceBits ||
					got.destination != destination || got.source != source {
					t.Fatalf("encoding %#08x decoded as %+v, ok=%v", word, got, ok)
				}
				count++
			}
		}
	}
	if count != 1536 {
		t.Fatalf("covered %d VMOVN forms, want 1536", count)
	}
}

func TestTranslateARMRawNEONMoveNarrowAllFormatsLLVM22(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawNarrow(SB), $0-0\n")
	for _, sourceBits := range []int{16, 32, 64} {
		word := encodeARMRawNEONMoveNarrow(sourceBits, 16, 16)
		fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
	}
	source.WriteString("\tRET\n")
	file, err := Parse(ArchARM, source.String())
	if err != nil {
		t.Fatal(err)
	}
	const triple = "armv7-unknown-linux-gnueabihf"
	ir, err := Translate(file, Options{
		Goarch: "arm", TargetTriple: triple,
		Sigs: map[string]FuncSig{"rawNarrow": {Name: "rawNarrow", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"trunc <8 x i16>", "trunc <4 x i32>", "trunc <2 x i64>",
	} {
		if !strings.Contains(ir, fragment) {
			t.Fatalf("raw VMOVN omitted %q:\n%s", fragment, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, triple, "arm-raw-neon-movn.ll", "arm-raw-neon-movn.o", ir)
}

func TestARMRawNEONMoveNarrowRejectsReservedFields(t *testing.T) {
	base := encodeARMRawNEONMoveNarrow(64, 0, 16)
	for _, word := range []uint32{
		base | 1,
		base ^ 1<<8,
		base | 1<<18,
	} {
		if _, ok := decodeARMRawNEONMoveNarrow(word); ok {
			t.Fatalf("accepted reserved VMOVN encoding %#08x", word)
		}
	}
}
