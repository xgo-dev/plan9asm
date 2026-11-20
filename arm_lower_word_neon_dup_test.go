package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARMRawNEONDup(condition, elementBits, destination, core int, quad bool) uint32 {
	word := uint32(condition)<<28 | 0x0e800b10 | uint32(destination&15)<<16 | uint32(core)<<12 | uint32(destination/16)<<7
	if quad {
		word |= 1 << 21
	}
	switch elementBits {
	case 8:
		word |= 1 << 22
	case 16:
		word |= 1 << 5
	}
	return word
}

func TestTranslateARMRawNEONDupCompleteForms(t *testing.T) {
	const source = `TEXT rawDup(SB), $0-0
	WORD $0xeec00b10 // vdup.8 d0, r0
	WORD $0xeee00b10 // vdup.8 q0, r0
	WORD $0xee834b30 // vdup.16 d3, r4
	WORD $0xeea64b30 // vdup.16 q3, r4
	WORD $0xee8feb10 // vdup.32 d15, r14
	WORD $0xeeaeeb10 // vdup.32 q7, r14
	RET
`
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"rawDup": {Name: "rawDup", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"shufflevector <8 x i8>", "shufflevector <4 x i16>", "shufflevector <2 x i32>", `"target-features"="+neon"`} {
		if !strings.Contains(ir, want) {
			t.Fatalf("raw NEON VDUP IR omitted %q:\n%s", want, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-raw-neon-dup.ll", "arm-raw-neon-dup.o", ir)
}

func TestARMRawNEONDupDecoderCoversEveryEncodingField(t *testing.T) {
	count := 0
	for condition := 0; condition < 15; condition++ {
		for _, elementBits := range []int{8, 16, 32} {
			for _, quad := range []bool{false, true} {
				step := 1
				if quad {
					step = 2
				}
				for destination := 0; destination < 32; destination += step {
					for core := 0; core < 16; core++ {
						word := encodeARMRawNEONDup(condition, elementBits, destination, core, quad)
						got, ok := decodeARMRawNEONDup(word)
						if !ok || got.condition != armConditionName(condition) || got.elementBits != elementBits || got.destination != destination || got.core != core || got.quad != quad {
							t.Fatalf("decoded NEON VDUP %#08x as %+v, ok=%v", word, got, ok)
						}
						count++
					}
				}
			}
		}
	}
	if count == 0 {
		t.Fatal("covered no NEON VDUP encodings")
	}
}

func TestARMRawNEONDupRejectsReservedAndUnsafeForms(t *testing.T) {
	reserved := encodeARMRawNEONDup(14, 8, 0, 0, false) | 1<<5
	if _, ok := decodeARMRawNEONDup(reserved); ok {
		t.Fatal("NEON VDUP decoder accepted reserved size encoding")
	}
	for _, word := range []uint32{encodeARMRawNEONDup(15, 8, 0, 0, false), encodeARMRawNEONDup(14, 8, 1, 0, true)} {
		if _, ok := decodeARMRawNEONDup(word); ok {
			t.Fatalf("NEON VDUP decoder accepted reserved encoding %#08x", word)
		}
	}
	word := encodeARMRawNEONDup(14, 8, 0, 15, false)
	file, err := Parse(ArchARM, fmt.Sprintf("TEXT badDup(SB), $0-0\n\tWORD $%#08x\n\tRET\n", word))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"badDup": {Name: "badDup", Ret: Void}}}); err == nil {
		t.Fatal("Translate accepted PC as NEON VDUP source")
	}
}
