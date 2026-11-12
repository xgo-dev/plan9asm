package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARMRawNEONTranspose(quad bool, elementBits, first, second int) uint32 {
	word := uint32(0xf3b20080 | (first&15)<<12 | (first/16)<<22 |
		second&15 | (second/16)<<5)
	switch elementBits {
	case 16:
		word |= 1 << 18
	case 32:
		word |= 2 << 18
	}
	if quad {
		word |= 1 << 6
	}
	return word
}

func TestARMRawNEONTransposeLLVM22Forms(t *testing.T) {
	for _, test := range []struct {
		word        uint32
		quad        bool
		elementBits int
		first       int
		second      int
	}{
		{0xf3b20081, false, 8, 0, 1},
		{0xf3b60081, false, 16, 0, 1},
		{0xf3ba008a, false, 32, 0, 10},
		{0xf3b200c2, true, 8, 0, 2},
		{0xf3b600c2, true, 16, 0, 2},
		{0xf3ba00c2, true, 32, 0, 2},
		{0xf3faf0a0, false, 32, 31, 16},
		{0xf3fae0e0, true, 32, 30, 16},
	} {
		got, ok := decodeARMRawNEONTranspose(test.word)
		if !ok || got.quad != test.quad || got.elementBits != test.elementBits ||
			got.first != test.first || got.second != test.second {
			t.Fatalf("LLVM 22 encoding %#08x decoded as %+v, ok=%v", test.word, got, ok)
		}
		if encoded := encodeARMRawNEONTranspose(
			test.quad, test.elementBits, test.first, test.second,
		); encoded != test.word {
			t.Fatalf("encoded %+v as %#08x, want %#08x", test, encoded, test.word)
		}
	}
}

func TestARMRawNEONTransposeAllRegisterFields(t *testing.T) {
	count := 0
	for _, elementBits := range []int{8, 16, 32} {
		for _, quad := range []bool{false, true} {
			step := 1
			if quad {
				step = 2
			}
			for first := 0; first < 32; first += step {
				for second := 0; second < 32; second += step {
					word := encodeARMRawNEONTranspose(quad, elementBits, first, second)
					got, ok := decodeARMRawNEONTranspose(word)
					if !ok || got.quad != quad || got.elementBits != elementBits ||
						got.first != first || got.second != second {
						t.Fatalf("encoding %#08x decoded as %+v, ok=%v", word, got, ok)
					}
					count++
				}
			}
		}
	}
	if count != 3840 {
		t.Fatalf("covered %d VTRN forms, want 3840", count)
	}
}

func TestTranslateARMRawNEONTransposeAllFormatsLLVM22(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawTranspose(SB), $0-0\n")
	for _, elementBits := range []int{8, 16, 32} {
		for _, quad := range []bool{false, true} {
			word := encodeARMRawNEONTranspose(quad, elementBits, 16, 18)
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
		Sigs: map[string]FuncSig{"rawTranspose": {Name: "rawTranspose", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"shufflevector <8 x i8>", "shufflevector <16 x i8>",
		"shufflevector <4 x i16>", "shufflevector <8 x i16>",
		"shufflevector <2 x i32>", "shufflevector <4 x i32>",
	} {
		if !strings.Contains(ir, fragment) {
			t.Fatalf("raw VTRN omitted %q:\n%s", fragment, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, triple, "arm-raw-neon-vtrn.ll", "arm-raw-neon-vtrn.o", ir)
}

func TestARMRawNEONTransposeRejectsReservedFields(t *testing.T) {
	base := encodeARMRawNEONTranspose(true, 32, 0, 2)
	for _, word := range []uint32{
		base | 1<<12,
		base | 1,
		base ^ 1<<8,
		base | 1<<18,
	} {
		if _, ok := decodeARMRawNEONTranspose(word); ok {
			t.Fatalf("accepted reserved VTRN encoding %#08x", word)
		}
	}
}
