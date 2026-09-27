package plan9asm

import (
	"strings"
	"testing"
)

func encodeARMRawNEONMoveLong(unsigned bool, elementBits, destination, source int) uint32 {
	word := uint32(0xf2800a10 | (destination&15)<<12 | source&15)
	if unsigned {
		word |= 1 << 24
	}
	word |= uint32(destination/16) << 22
	word |= uint32(map[int]int{8: 0b001000, 16: 0b010000, 32: 0b100000}[elementBits]) << 16
	word |= uint32(source/16) << 5
	return word
}

func TestTranslateARMRawNEONVMOVLGoDSPRegression(t *testing.T) {
	const source = `TEXT rawMoveLong(SB), $0-0
	WORD $0xf2902a34 // vmovl.s16 q1, d20
	RET
`
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"rawMoveLong": {Name: "rawMoveLong", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"sext <4 x i16>", `"target-features"="+neon"`} {
		if !strings.Contains(ir, want) {
			t.Fatalf("raw NEON VMOVL IR omitted %q:\n%s", want, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-raw-neon-vmovl.ll", "arm-raw-neon-vmovl.o", ir)
}

func TestARMRawNEONVMOVLDecoderCoversEveryEncodingField(t *testing.T) {
	count := 0
	for _, unsigned := range []bool{false, true} {
		for _, elementBits := range []int{8, 16, 32} {
			for destination := 0; destination < 32; destination += 2 {
				for source := 0; source < 32; source++ {
					word := encodeARMRawNEONMoveLong(unsigned, elementBits, destination, source)
					got, ok := decodeARMRawNEONMoveLong(word)
					if !ok || got.unsigned != unsigned || got.elementBits != elementBits || got.destination != destination || got.source != source {
						t.Fatalf("decoded NEON VMOVL %#08x as %+v, ok=%v", word, got, ok)
					}
					count++
				}
			}
		}
	}
	if count != 3072 {
		t.Fatalf("covered %d NEON VMOVL encodings, want 3072", count)
	}
}

func TestARMRawNEONVMOVLRejectsReservedForms(t *testing.T) {
	for _, word := range []uint32{
		encodeARMRawNEONMoveLong(false, 8, 0, 0) &^ (uint32(0x3f) << 16),
		encodeARMRawNEONMoveLong(false, 8, 0, 0) | 1<<12,
		encodeARMRawNEONMoveLong(false, 8, 0, 0) | 1<<6,
	} {
		if _, ok := decodeARMRawNEONMoveLong(word); ok {
			t.Fatalf("NEON VMOVL decoder accepted reserved encoding %#08x", word)
		}
	}

	const unsignedSource = `TEXT rawUnsignedMoveLong(SB), $0-0
	WORD $0xf3880a10 // vmovl.u8 q0, d0
	RET
`
	file, err := Parse(ArchARM, unsignedSource)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"rawUnsignedMoveLong": {Name: "rawUnsignedMoveLong", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "zext <8 x i8>") {
		t.Fatalf("unsigned NEON VMOVL omitted zero extension:\n%s", ir)
	}
}
