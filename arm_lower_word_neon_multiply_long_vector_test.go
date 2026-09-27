package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARMRawNEONMultiplyLongVector(kind string, unsigned bool, elementBits, destination, lhs, rhs int) uint32 {
	word := uint32(0xf2800c00 | (destination&15)<<12 | (lhs&15)<<16 | rhs&15)
	switch kind {
	case "mla":
		word &^= 0x400
	case "mls":
		word &^= 0x400
		word |= 0x200
	}
	if unsigned {
		word |= 1 << 24
	}
	word |= uint32(map[int]int{8: 0, 16: 1, 32: 2}[elementBits]) << 20
	word |= uint32(destination/16) << 22
	word |= uint32(lhs/16) << 7
	word |= uint32(rhs/16) << 5
	return word
}

func TestARMRawNEONMultiplyLongVectorLLVM22Forms(t *testing.T) {
	for _, test := range []struct {
		word        uint32
		kind        string
		unsigned    bool
		elementBits int
		destination int
		lhs         int
		rhs         int
	}{
		{0xf2810c02, "mul", false, 8, 0, 1, 2},
		{0xf3810c02, "mul", true, 8, 0, 1, 2},
		{0xf2910c02, "mul", false, 16, 0, 1, 2},
		{0xf3910c02, "mul", true, 16, 0, 1, 2},
		{0xf2a10c02, "mul", false, 32, 0, 1, 2},
		{0xf3a9ec80, "mul", true, 32, 14, 25, 0},
		{0xf2810802, "mla", false, 8, 0, 1, 2},
		{0xf3810802, "mla", true, 8, 0, 1, 2},
		{0xf2910802, "mla", false, 16, 0, 1, 2},
		{0xf3910802, "mla", true, 16, 0, 1, 2},
		{0xf2a10802, "mla", false, 32, 0, 1, 2},
		{0xf3a10802, "mla", true, 32, 0, 1, 2},
		{0xf2810a02, "mls", false, 8, 0, 1, 2},
		{0xf3810a02, "mls", true, 8, 0, 1, 2},
		{0xf2910a02, "mls", false, 16, 0, 1, 2},
		{0xf3910a02, "mls", true, 16, 0, 1, 2},
		{0xf2a10a02, "mls", false, 32, 0, 1, 2},
		{0xf3a10a02, "mls", true, 32, 0, 1, 2},
	} {
		got, ok := decodeARMRawNEONMultiplyLongVector(test.word)
		if !ok || got.kind != test.kind || got.unsigned != test.unsigned ||
			got.elementBits != test.elementBits || got.destination != test.destination ||
			got.lhs != test.lhs || got.rhs != test.rhs {
			t.Fatalf("LLVM 22 encoding %#08x decoded as %+v, ok=%v", test.word, got, ok)
		}
		if encoded := encodeARMRawNEONMultiplyLongVector(
			test.kind, test.unsigned, test.elementBits, test.destination, test.lhs, test.rhs,
		); encoded != test.word {
			t.Fatalf("encoded %+v as %#08x, want %#08x", test, encoded, test.word)
		}
	}
}

func TestARMRawNEONMultiplyLongVectorAllFields(t *testing.T) {
	count := 0
	for _, kind := range []string{"mul", "mla", "mls"} {
		for _, unsigned := range []bool{false, true} {
			for _, elementBits := range []int{8, 16, 32} {
				for destination := 0; destination < 32; destination += 2 {
					for lhs := 0; lhs < 32; lhs++ {
						for rhs := 0; rhs < 32; rhs++ {
							word := encodeARMRawNEONMultiplyLongVector(
								kind, unsigned, elementBits, destination, lhs, rhs,
							)
							got, ok := decodeARMRawNEONMultiplyLongVector(word)
							if !ok || got.kind != kind || got.unsigned != unsigned ||
								got.elementBits != elementBits || got.destination != destination ||
								got.lhs != lhs || got.rhs != rhs {
								t.Fatalf("encoding %#08x decoded as %+v, ok=%v", word, got, ok)
							}
							count++
						}
					}
				}
			}
		}
	}
	if count != 294912 {
		t.Fatalf("covered %d VMULL/VMLAL/VMLSL vector forms, want 294912", count)
	}
}

func TestTranslateARMRawNEONMultiplyLongVectorLLVM22(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawWideningMultiplyVector(SB), $0-0\n")
	for _, kind := range []string{"mul", "mla", "mls"} {
		for _, unsigned := range []bool{false, true} {
			for _, elementBits := range []int{8, 16, 32} {
				word := encodeARMRawNEONMultiplyLongVector(kind, unsigned, elementBits, 10, 2, 4)
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
		Sigs: map[string]FuncSig{"rawWideningMultiplyVector": {Name: "rawWideningMultiplyVector", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"mul <8 x i16>", "mul <4 x i32>", "mul <2 x i64>",
		"add <8 x i16>", "sub <2 x i64>", "sext <8 x i8>", "zext <8 x i8>",
	} {
		if !strings.Contains(ir, fragment) {
			t.Fatalf("raw VMULL/VMLAL/VMLSL omitted %q:\n%s", fragment, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, triple, "arm-raw-neon-multiply-long-vector.ll", "arm-raw-neon-multiply-long-vector.o", ir)
}

func TestARMRawNEONMultiplyLongVectorRejectsReservedForms(t *testing.T) {
	base := encodeARMRawNEONMultiplyLongVector("mul", false, 8, 0, 0, 0)
	for _, word := range []uint32{
		base | 3<<20,
		base | 1<<12,
		base | 1<<4,
		base | 1<<6,
	} {
		if _, ok := decodeARMRawNEONMultiplyLongVector(word); ok {
			t.Fatalf("accepted reserved multiply-long vector encoding %#08x", word)
		}
	}
}
