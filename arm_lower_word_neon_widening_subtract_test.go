package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARMRawNEONWideningSubtract(unsigned bool, elementBits, destination, lhs, rhs int) uint32 {
	word := uint32(0xf2800200 | (destination&15)<<12 | (lhs&15)<<16 | rhs&15)
	if unsigned {
		word |= 1 << 24
	}
	word |= uint32(destination/16) << 22
	word |= uint32(map[int]int{8: 0, 16: 1, 32: 2}[elementBits]) << 20
	word |= uint32(lhs/16) << 7
	word |= uint32(rhs/16) << 5
	return word
}

func encodeARMRawNEONWideningAdd(unsigned bool, elementBits, destination, lhs, rhs int) uint32 {
	return encodeARMRawNEONWideningSubtract(unsigned, elementBits, destination, lhs, rhs) &^ (1 << 9)
}

func TestARMRawNEONWideningAddLLVM22Forms(t *testing.T) {
	for _, test := range []struct {
		word        uint32
		unsigned    bool
		elementBits int
		destination int
		lhs         int
		rhs         int
	}{
		{0xf2810002, false, 8, 0, 1, 2},
		{0xf3810002, true, 8, 0, 1, 2},
		{0xf2910002, false, 16, 0, 1, 2},
		{0xf3910002, true, 16, 0, 1, 2},
		{0xf2a10002, false, 32, 0, 1, 2},
		{0xf3aaa02e, true, 32, 10, 10, 30},
	} {
		got, ok := decodeARMRawNEONWideningAddSub(test.word)
		if !ok || got.operation != "add" || got.unsigned != test.unsigned ||
			got.elementBits != test.elementBits || got.destination != test.destination ||
			got.lhs != test.lhs || got.rhs != test.rhs {
			t.Fatalf("LLVM 22 VADDL encoding %#08x decoded as %+v, ok=%v", test.word, got, ok)
		}
		if encoded := encodeARMRawNEONWideningAdd(
			test.unsigned, test.elementBits, test.destination, test.lhs, test.rhs,
		); encoded != test.word {
			t.Fatalf("encoded %+v as %#08x, want %#08x", test, encoded, test.word)
		}
	}
}

func TestARMRawNEONWideningAddAllRegisterFields(t *testing.T) {
	count := 0
	for _, unsigned := range []bool{false, true} {
		for _, elementBits := range []int{8, 16, 32} {
			for destination := 0; destination < 32; destination += 2 {
				for lhs := 0; lhs < 32; lhs++ {
					for rhs := 0; rhs < 32; rhs++ {
						word := encodeARMRawNEONWideningAdd(
							unsigned, elementBits, destination, lhs, rhs,
						)
						got, ok := decodeARMRawNEONWideningAddSub(word)
						if !ok || got.operation != "add" || got.unsigned != unsigned ||
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
	if count != 98304 {
		t.Fatalf("covered %d VADDL forms, want 98304", count)
	}
}

func TestTranslateARMRawNEONWideningAddLLVM22(t *testing.T) {
	source := "TEXT rawWideningAdd(SB), $0-0\n"
	for _, unsigned := range []bool{false, true} {
		for _, elementBits := range []int{8, 16, 32} {
			word := encodeARMRawNEONWideningAdd(unsigned, elementBits, 10, 2, 4)
			source += fmt.Sprintf("\tWORD $%#08x\n", word)
		}
	}
	source += "\tRET\n"
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	const triple = "armv7-unknown-linux-gnueabihf"
	ir, err := Translate(file, Options{
		Goarch: "arm", TargetTriple: triple,
		Sigs: map[string]FuncSig{"rawWideningAdd": {Name: "rawWideningAdd", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"add <8 x i16>", "add <4 x i32>", "add <2 x i64>",
		"sext <8 x i8>", "zext <8 x i8>",
	} {
		if !strings.Contains(ir, fragment) {
			t.Fatalf("raw VADDL omitted %q:\n%s", fragment, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, triple, "arm-raw-neon-vaddl.ll", "arm-raw-neon-vaddl.o", ir)
}

func TestTranslateARMRawNEONVSUBLGoDSPRegression(t *testing.T) {
	const source = `TEXT rawWideningSubtract(SB), $0-0
	WORD $0xf3cc4280 // vsubl.u8 q10, d28, d0
	RET
`
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"rawWideningSubtract": {Name: "rawWideningSubtract", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"zext <8 x i8>", "sub <8 x i16>", `"target-features"="+neon"`} {
		if !strings.Contains(ir, want) {
			t.Fatalf("raw NEON VSUBL IR omitted %q:\n%s", want, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-raw-neon-vsubl.ll", "arm-raw-neon-vsubl.o", ir)
}

func TestARMRawNEONVSUBLDecoderCoversEveryEncodingField(t *testing.T) {
	count := 0
	for _, unsigned := range []bool{false, true} {
		for _, elementBits := range []int{8, 16, 32} {
			for destination := 0; destination < 32; destination += 2 {
				for lhs := 0; lhs < 32; lhs++ {
					for rhs := 0; rhs < 32; rhs++ {
						word := encodeARMRawNEONWideningSubtract(unsigned, elementBits, destination, lhs, rhs)
						got, ok := decodeARMRawNEONWideningSubtract(word)
						if !ok || got.unsigned != unsigned || got.elementBits != elementBits || got.destination != destination || got.lhs != lhs || got.rhs != rhs {
							t.Fatalf("decoded NEON VSUBL %#08x as %+v, ok=%v", word, got, ok)
						}
						count++
					}
				}
			}
		}
	}
	if count != 98304 {
		t.Fatalf("covered %d NEON VSUBL encodings, want 98304", count)
	}
}

func TestARMRawNEONVSUBLRejectsReservedForms(t *testing.T) {
	for _, word := range []uint32{
		encodeARMRawNEONWideningSubtract(false, 8, 0, 0, 0) | 3<<20,
		encodeARMRawNEONWideningSubtract(false, 8, 0, 0, 0) | 1<<12,
		encodeARMRawNEONWideningSubtract(false, 8, 0, 0, 0) | 1<<6,
	} {
		if _, ok := decodeARMRawNEONWideningSubtract(word); ok {
			t.Fatalf("NEON VSUBL decoder accepted reserved encoding %#08x", word)
		}
	}
	if _, ok := decodeARMRawNEONWideningSubtract(encodeARMRawNEONWideningSubtract(true, 32, 30, 31, 31)); !ok {
		t.Fatal("NEON VSUBL decoder rejected last valid registers")
	}

	const signedSource = `TEXT rawSignedWideningSubtract(SB), $0-0
	WORD $0xf28c4280 // vsubl.s8 q2, d28, d0
	RET
`
	file, err := Parse(ArchARM, signedSource)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"rawSignedWideningSubtract": {Name: "rawSignedWideningSubtract", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "sext <8 x i8>") {
		t.Fatalf("signed NEON VSUBL omitted sign extension:\n%s", ir)
	}
}
