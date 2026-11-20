package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARMRawNEONStructureOne(load bool, base, offset, first, count, elementBits, alignment int) uint32 {
	typeField := map[int]int{1: 0b0111, 2: 0b1010, 3: 0b0110, 4: 0b0010}[count]
	word := uint32(0xf4000000 | base<<16 | (first&15)<<12 | typeField<<8 | offset)
	if load {
		word |= 1 << 21
	}
	word |= uint32(first/16) << 22
	word |= uint32(map[int]int{8: 0, 16: 1, 32: 2, 64: 3}[elementBits]) << 6
	word |= uint32(map[int]int{0: 0, 8: 1, 16: 2, 32: 3}[alignment]) << 4
	return word
}

func TestTranslateARMRawNEONVLD1VST1PionTransportRegression(t *testing.T) {
	const source = `TEXT rawStructure(SB), $0-0
	WORD $0xF421020D // vld1.u8 {q0, q1}, [r1]!
	WORD $0xF422420D // vld1.u8 {q2, q3}, [r2]!
	WORD $0xF400420D // vst1.u8 {q2, q3}, [r0]!
	WORD $0xF4210A0D // vld1.u8 q0, [r1]!
	WORD $0xF4002A0D // vst1.u8 q1, [r0]!
	WORD $0xF421070D // vld1.u8 d0, [r1]!
	WORD $0xF400170D // vst1.u8 d1, [r0]!
	RET
`
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"rawStructure": {Name: "rawStructure", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"load i64, ptr", "store i64", `"target-features"="+neon"`} {
		if !strings.Contains(ir, want) {
			t.Fatalf("raw NEON VLD1/VST1 IR omitted %q:\n%s", want, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-raw-neon-structure.ll", "arm-raw-neon-structure.o", ir)
}

func TestARMRawNEONVLD1VST1DecoderCoversEveryEncodingField(t *testing.T) {
	countForms := 0
	alignmentsByCount := map[int][]int{1: {0, 8}, 2: {0, 8, 16}, 3: {0, 8}, 4: {0, 8, 16, 32}}
	for _, load := range []bool{false, true} {
		for count := 1; count <= 4; count++ {
			for _, elementBits := range []int{8, 16, 32, 64} {
				for _, alignment := range alignmentsByCount[count] {
					for first := 0; first+count <= 32; first++ {
						for base := 0; base < 16; base++ {
							for offset := 0; offset < 16; offset++ {
								word := encodeARMRawNEONStructureOne(load, base, offset, first, count, elementBits, alignment)
								got, ok := decodeARMRawNEONStructureOne(word)
								if !ok || got.load != load || got.base != base || got.offset != offset || got.first != first || got.count != count || got.elementBits != elementBits || got.alignment != alignment {
									t.Fatalf("decoded NEON VLD1/VST1 %#08x as %+v, ok=%v", word, got, ok)
								}
								countForms++
							}
						}
					}
				}
			}
		}
	}
	if countForms != 681984 {
		t.Fatalf("covered %d NEON VLD1/VST1 encodings, want 681984", countForms)
	}
}

func TestARMRawNEONVLD1VST1RejectsReservedAndUnsafeForms(t *testing.T) {
	for _, word := range []uint32{
		encodeARMRawNEONStructureOne(true, 0, 15, 31, 1, 32, 0) &^ (uint32(15) << 8),
		encodeARMRawNEONStructureOne(true, 0, 15, 0, 1, 32, 0) | 2<<4,
		encodeARMRawNEONStructureOne(true, 0, 15, 31, 4, 32, 0),
	} {
		if _, ok := decodeARMRawNEONStructureOne(word); ok {
			t.Fatalf("NEON VLD1/VST1 decoder accepted reserved encoding %#08x", word)
		}
	}

	word := encodeARMRawNEONStructureOne(true, 15, 13, 0, 4, 32, 0)
	file, err := Parse(ArchARM, fmt.Sprintf("TEXT badStructure(SB), $0-0\n\tWORD $%#08x\n\tRET\n", word))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"badStructure": {Name: "badStructure", Ret: Void}}}); err == nil {
		t.Fatal("Translate accepted PC as NEON VLD1/VST1 base")
	}
}

func TestTranslateARMRawNEONVLD1VST1AddressingModes(t *testing.T) {
	source := "TEXT rawStructureModes(SB), $0-0\n"
	for _, word := range []uint32{
		encodeARMRawNEONStructureOne(true, 0, 15, 0, 1, 8, 8),
		encodeARMRawNEONStructureOne(true, 1, 13, 1, 2, 16, 16),
		encodeARMRawNEONStructureOne(false, 2, 4, 3, 3, 32, 8),
		encodeARMRawNEONStructureOne(false, 3, 13, 6, 4, 64, 32),
	} {
		source += fmt.Sprintf("\tWORD $%#08x\n", word)
	}
	source += "\tRET\n"
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"rawStructureModes": {Name: "rawStructureModes", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"align 8", "align 16", "align 32", "add i32", `"target-features"="+neon"`} {
		if !strings.Contains(ir, want) {
			t.Fatalf("raw NEON VLD1/VST1 addressing IR omitted %q:\n%s", want, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-raw-neon-structure-modes.ll", "arm-raw-neon-structure-modes.o", ir)
}
