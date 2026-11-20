package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARMRawNEONVMAXGoDSPRegression(t *testing.T) {
	const source = `TEXT rawMaximum(SB), $0-0
	WORD $0xf2088f42 // vmax.f32 q4, q4, q1
	RET
`
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"rawMaximum": {Name: "rawMaximum", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "@llvm.maximum.v4f32") {
		t.Fatalf("raw NEON VMAX.F32 IR omitted maximum intrinsic:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-raw-neon-vmax.ll", "arm-raw-neon-vmax.o", ir)
}

func encodeARMRawNEONMinMax(minimum, floating, unsigned, quad bool, elementBits, destination, lhs, rhs int) uint32 {
	word := uint32(0xf2000000 | (destination&15)<<12 | (lhs&15)<<16 | rhs&15)
	word |= uint32(destination/16) << 22
	word |= uint32(lhs/16) << 7
	word |= uint32(rhs/16) << 5
	if quad {
		word |= 1 << 6
	}
	if floating {
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
		word |= 0b0110 << 8
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

func TestARMRawNEONMinMaxDecoderCoversEveryEncodingField(t *testing.T) {
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
				for _, quad := range []bool{false, true} {
					step := 1
					if quad {
						step = 2
					}
					for _, elementBits := range elementSizes {
						for destination := 0; destination < 32; destination += step {
							for lhs := 0; lhs < 32; lhs += step {
								for rhs := 0; rhs < 32; rhs += step {
									word := encodeARMRawNEONMinMax(minimum, floating, unsigned, quad, elementBits, destination, lhs, rhs)
									got, ok := decodeARMRawNEONMinMax(word)
									if !ok || got.minimum != minimum || got.floating != floating || got.unsigned != unsigned || got.quad != quad || got.elementBits != elementBits || got.destination != destination || got.lhs != lhs || got.rhs != rhs {
										t.Fatalf("decoded NEON min/max %#08x as %+v, ok=%v", word, got, ok)
									}
									count++
								}
							}
						}
					}
				}
			}
		}
	}
	if count != 589824 {
		t.Fatalf("covered %d NEON min/max encodings, want 589824", count)
	}
}

func TestTranslateARMRawNEONMinMaxAllFormats(t *testing.T) {
	source := "TEXT rawMinMaxAll(SB), $0-0\n"
	for _, minimum := range []bool{false, true} {
		for _, unsigned := range []bool{false, true} {
			for _, quad := range []bool{false, true} {
				for _, bits := range []int{8, 16, 32} {
					source += fmt.Sprintf("\tWORD $%#08x\n", encodeARMRawNEONMinMax(minimum, false, unsigned, quad, bits, 0, 2, 4))
				}
			}
		}
		for _, quad := range []bool{false, true} {
			for _, bits := range []int{16, 32} {
				source += fmt.Sprintf("\tWORD $%#08x\n", encodeARMRawNEONMinMax(minimum, true, false, quad, bits, 0, 2, 4))
			}
		}
	}
	source += "\tRET\n"
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"rawMinMaxAll": {Name: "rawMinMaxAll", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"icmp sgt <8 x i8>", "icmp ugt <16 x i8>", "icmp slt <2 x i32>", "icmp ult <4 x i32>", "@llvm.maximum.v4f16", "@llvm.maximum.v4f32", "@llvm.minimum.v8f16", "@llvm.minimum.v2f32", "+fullfp16", "+neon"} {
		if !strings.Contains(ir, want) {
			t.Fatalf("raw NEON min/max formats omitted %q:\n%s", want, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-raw-neon-minmax-all.ll", "arm-raw-neon-minmax-all.o", ir)
}

func TestARMRawNEONMinMaxRejectsReservedForms(t *testing.T) {
	for _, word := range []uint32{
		encodeARMRawNEONMinMax(false, false, false, false, 8, 0, 0, 0) | 3<<20,
		encodeARMRawNEONMinMax(false, true, false, false, 32, 0, 0, 0) | 1<<24,
		encodeARMRawNEONMinMax(false, true, false, false, 32, 0, 0, 0) | 1<<4,
		encodeARMRawNEONMinMax(false, false, false, true, 8, 0, 0, 0) | 1<<12,
		encodeARMRawNEONMinMax(false, false, false, true, 8, 0, 0, 0) | 1<<16,
		encodeARMRawNEONMinMax(false, false, false, true, 8, 0, 0, 0) | 1,
	} {
		if _, ok := decodeARMRawNEONMinMax(word); ok {
			t.Fatalf("NEON min/max decoder accepted reserved encoding %#08x", word)
		}
	}
}
