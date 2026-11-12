package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARMRawNEONAddSub(subtract, floating, quad bool, elementBits, destination, lhs, rhs int) uint32 {
	word := uint32(0xf2000800)
	if floating {
		word = 0xf2000d00
		if elementBits == 16 {
			word |= 1 << 20
		}
		if subtract {
			word |= 1 << 21
		}
	} else {
		if subtract {
			word |= 1 << 24
		}
		for bits := 8; bits < elementBits; bits *= 2 {
			word += 1 << 20
		}
	}
	word |= uint32(destination&15)<<12 | uint32(destination/16)<<22
	word |= uint32(lhs&15)<<16 | uint32(lhs/16)<<7
	word |= uint32(rhs&15) | uint32(rhs/16)<<5
	if quad {
		word |= 1 << 6
	}
	return word
}

func TestARMRawNEONAddSubLLVM22Forms(t *testing.T) {
	for _, test := range []struct {
		word        uint32
		subtract    bool
		floating    bool
		quad        bool
		elementBits int
		destination int
		lhs         int
		rhs         int
	}{
		{0xf2010802, false, false, false, 8, 0, 1, 2},
		{0xf2110802, false, false, false, 16, 0, 1, 2},
		{0xf2210802, false, false, false, 32, 0, 1, 2},
		{0xf2310802, false, false, false, 64, 0, 1, 2},
		{0xf2020844, false, false, true, 8, 0, 2, 4},
		{0xf226e868, false, false, true, 32, 14, 6, 24},
		{0xf326e868, true, false, true, 32, 14, 6, 24},
		{0xf2010d02, false, true, false, 32, 0, 1, 2},
		{0xf2110d02, false, true, false, 16, 0, 1, 2},
		{0xf2210d02, true, true, false, 32, 0, 1, 2},
		{0xf2310d02, true, true, false, 16, 0, 1, 2},
	} {
		got, ok := decodeARMRawNEONAddSub(test.word)
		if !ok || got.subtract != test.subtract || got.floating != test.floating ||
			got.quad != test.quad || got.elementBits != test.elementBits ||
			got.destination != test.destination || got.lhs != test.lhs || got.rhs != test.rhs {
			t.Fatalf("LLVM 22 encoding %#08x decoded as %+v, ok=%v", test.word, got, ok)
		}
		if encoded := encodeARMRawNEONAddSub(
			test.subtract, test.floating, test.quad, test.elementBits,
			test.destination, test.lhs, test.rhs,
		); encoded != test.word {
			t.Fatalf("encoded %+v as %#08x, want %#08x", test, encoded, test.word)
		}
	}
}

func TestARMRawNEONAddSubAllFields(t *testing.T) {
	count := 0
	for _, floating := range []bool{false, true} {
		widths := []int{8, 16, 32, 64}
		if floating {
			widths = []int{16, 32}
		}
		for _, elementBits := range widths {
			for _, subtract := range []bool{false, true} {
				for _, quad := range []bool{false, true} {
					step := 1
					if quad {
						step = 2
					}
					for destination := 0; destination < 32; destination += step {
						for lhs := 0; lhs < 32; lhs += step {
							for rhs := 0; rhs < 32; rhs += step {
								word := encodeARMRawNEONAddSub(
									subtract, floating, quad, elementBits, destination, lhs, rhs,
								)
								got, ok := decodeARMRawNEONAddSub(word)
								if !ok || got.subtract != subtract || got.floating != floating ||
									got.quad != quad || got.elementBits != elementBits ||
									got.destination != destination || got.lhs != lhs || got.rhs != rhs {
									t.Fatalf("encoding %#08x decoded as %+v, ok=%v", word, got, ok)
								}
								count++
							}
						}
					}
				}
			}
		}
	}
	if count != 442368 {
		t.Fatalf("covered %d NEON VADD/VSUB forms, want 442368", count)
	}
}

func TestTranslateARMRawNEONAddSubAllFormatsLLVM22(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawAddSub(SB), $0-0\n")
	for _, floating := range []bool{false, true} {
		widths := []int{8, 16, 32, 64}
		if floating {
			widths = []int{16, 32}
		}
		for _, elementBits := range widths {
			for _, subtract := range []bool{false, true} {
				for _, quad := range []bool{false, true} {
					word := encodeARMRawNEONAddSub(subtract, floating, quad, elementBits, 0, 2, 4)
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
		Sigs: map[string]FuncSig{"rawAddSub": {Name: "rawAddSub", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"add <8 x i8>", "sub <8 x i8>", "add <4 x i16>", "sub <4 x i16>",
		"add <2 x i32>", "sub <2 x i32>", "add <1 x i64>", "sub <1 x i64>",
		"fadd <4 x half>", "fsub <4 x half>", "fadd <2 x float>", "fsub <2 x float>",
	} {
		if !strings.Contains(ir, fragment) {
			t.Fatalf("raw VADD/VSUB omitted %q:\n%s", fragment, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, triple, "arm-raw-neon-add-sub.ll", "arm-raw-neon-add-sub.o", ir)
}

func TestARMRawNEONAddSubRejectsReservedFields(t *testing.T) {
	base := encodeARMRawNEONAddSub(false, false, true, 32, 0, 2, 4)
	for _, word := range []uint32{
		base | 1<<12,
		base | 1<<16,
		base | 1,
		base ^ 1<<9,
	} {
		if _, ok := decodeARMRawNEONAddSub(word); ok {
			t.Fatalf("accepted reserved VADD/VSUB encoding %#08x", word)
		}
	}
}
