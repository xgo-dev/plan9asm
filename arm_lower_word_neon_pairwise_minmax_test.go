package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARMRawNEONVPMAXGoDSPRegression(t *testing.T) {
	const source = `TEXT rawPairwiseMaximum(SB), $0-0
	WORD $0xf3004f01 // vpmax.f32 d4, d0, d1
	RET
`
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"rawPairwiseMaximum": {Name: "rawPairwiseMaximum", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "@llvm.maximum.f32") {
		t.Fatalf("raw NEON VPMAX.F32 IR omitted maximum intrinsic:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-raw-neon-vpmax.ll", "arm-raw-neon-vpmax.o", ir)
}

func encodeARMRawNEONPairwiseMinMax(minimum, floating, unsigned bool, elementBits, destination, lhs, rhs int) uint32 {
	word := uint32(0xf2000000 | (destination&15)<<12 | (lhs&15)<<16 | rhs&15)
	word |= uint32(destination/16) << 22
	word |= uint32(lhs/16) << 7
	word |= uint32(rhs/16) << 5
	if floating {
		word |= 1 << 24
		word |= 0b1111 << 8
		size := 0
		if elementBits == 16 {
			size = 1
		}
		if minimum {
			size += 2
		}
		word |= uint32(size) << 20
	} else {
		word |= 0b1010 << 8
		word |= uint32(map[int]int{8: 0, 16: 1, 32: 2}[elementBits]) << 20
		if unsigned {
			word |= 1 << 24
		}
		if minimum {
			word |= 1 << 4
		}
	}
	return word
}

func TestARMRawNEONPairwiseMinMaxDecoderCoversEveryEncodingField(t *testing.T) {
	count := 0
	for _, floating := range []bool{false, true} {
		for _, minimum := range []bool{false, true} {
			unsignedValues := []bool{false, true}
			elementSizes := []int{8, 16, 32}
			if floating {
				unsignedValues = []bool{false}
				elementSizes = []int{16, 32}
			}
			for _, unsigned := range unsignedValues {
				for _, elementBits := range elementSizes {
					for destination := 0; destination < 32; destination++ {
						for lhs := 0; lhs < 32; lhs++ {
							for rhs := 0; rhs < 32; rhs++ {
								word := encodeARMRawNEONPairwiseMinMax(minimum, floating, unsigned, elementBits, destination, lhs, rhs)
								got, ok := decodeARMRawNEONPairwiseMinMax(word)
								if !ok || got.minimum != minimum || got.floating != floating || got.unsigned != unsigned || got.elementBits != elementBits || got.destination != destination || got.lhs != lhs || got.rhs != rhs {
									t.Fatalf("decoded NEON pairwise min/max %#08x as %+v, ok=%v", word, got, ok)
								}
								count++
							}
						}
					}
				}
			}
		}
	}
	if count != 524288 {
		t.Fatalf("covered %d NEON pairwise min/max encodings, want 524288", count)
	}
}

func TestTranslateARMRawNEONPairwiseMinMaxAllFormats(t *testing.T) {
	source := "TEXT rawPairwiseMinMaxAll(SB), $0-0\n"
	for _, minimum := range []bool{false, true} {
		for _, unsigned := range []bool{false, true} {
			for _, bits := range []int{8, 16, 32} {
				source += fmt.Sprintf("\tWORD $%#08x\n", encodeARMRawNEONPairwiseMinMax(minimum, false, unsigned, bits, 0, 1, 2))
			}
		}
		for _, bits := range []int{16, 32} {
			source += fmt.Sprintf("\tWORD $%#08x\n", encodeARMRawNEONPairwiseMinMax(minimum, true, false, bits, 0, 1, 2))
		}
	}
	source += "\tRET\n"
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"rawPairwiseMinMaxAll": {Name: "rawPairwiseMinMaxAll", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"icmp sgt i8", "icmp ugt i16", "icmp slt i32", "icmp ult i8", "@llvm.maximum.f16", "@llvm.maximum.f32", "@llvm.minimum.f16", "@llvm.minimum.f32", "+fullfp16", "+neon"} {
		if !strings.Contains(ir, want) {
			t.Fatalf("raw NEON pairwise min/max formats omitted %q:\n%s", want, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-raw-neon-pairwise-minmax-all.ll", "arm-raw-neon-pairwise-minmax-all.o", ir)
}

func TestARMRawNEONPairwiseMinMaxRejectsReservedForms(t *testing.T) {
	for _, word := range []uint32{
		encodeARMRawNEONPairwiseMinMax(false, false, false, 8, 0, 0, 0) | 3<<20,
		encodeARMRawNEONPairwiseMinMax(false, true, false, 32, 0, 0, 0) &^ (1 << 24),
		encodeARMRawNEONPairwiseMinMax(false, true, false, 32, 0, 0, 0) | 1<<4,
		encodeARMRawNEONPairwiseMinMax(false, false, false, 8, 0, 0, 0) | 1<<6,
	} {
		if _, ok := decodeARMRawNEONPairwiseMinMax(word); ok {
			t.Fatalf("NEON pairwise min/max decoder accepted reserved encoding %#08x", word)
		}
	}
}
