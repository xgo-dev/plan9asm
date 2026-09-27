package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARMRawNEONConvertFloat32(toFloat, unsigned, quad bool, destination, source int) uint32 {
	op := 0b01100
	if !toFloat {
		op = 0b01110
	}
	if unsigned {
		op++
	}
	word := uint32(0xf3bb0000 | (destination&15)<<12 | op<<7 | source&15)
	word |= uint32(destination/16) << 22
	word |= uint32(source/16) << 5
	if quad {
		word |= 1 << 6
	}
	return word
}

func TestTranslateARMRawNEONVCVTFloat32GoDSPRegression(t *testing.T) {
	const source = `TEXT rawConvertFloat32(SB), $0-0
	WORD $0xf3bb2642 // vcvt.f32.s32 q1, q1
	RET
`
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"rawConvertFloat32": {Name: "rawConvertFloat32", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"sitofp <4 x i32>", `"target-features"="+neon"`} {
		if !strings.Contains(ir, want) {
			t.Fatalf("raw NEON VCVT IR omitted %q:\n%s", want, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-raw-neon-vcvt.ll", "arm-raw-neon-vcvt.o", ir)
}

func TestARMRawNEONVCVTFloat32DecoderCoversEveryEncodingField(t *testing.T) {
	count := 0
	for _, toFloat := range []bool{false, true} {
		for _, unsigned := range []bool{false, true} {
			for _, quad := range []bool{false, true} {
				step := 1
				if quad {
					step = 2
				}
				for destination := 0; destination < 32; destination += step {
					for source := 0; source < 32; source += step {
						word := encodeARMRawNEONConvertFloat32(toFloat, unsigned, quad, destination, source)
						got, ok := decodeARMRawNEONConvertFloat32(word)
						if !ok || got.toFloat != toFloat || got.unsigned != unsigned || got.quad != quad || got.destination != destination || got.source != source {
							t.Fatalf("decoded NEON VCVT %#08x as %+v, ok=%v", word, got, ok)
						}
						count++
					}
				}
			}
		}
	}
	if count != 5120 {
		t.Fatalf("covered %d NEON VCVT encodings, want 5120", count)
	}
}

func TestTranslateARMRawNEONVCVTFloat32AllOperations(t *testing.T) {
	source := "TEXT rawConvertFloat32All(SB), $0-0\n"
	for _, test := range []struct {
		toFloat  bool
		unsigned bool
		quad     bool
	}{
		{true, false, false}, {true, true, false}, {false, false, false}, {false, true, false},
		{true, false, true}, {true, true, true}, {false, false, true}, {false, true, true},
	} {
		word := encodeARMRawNEONConvertFloat32(test.toFloat, test.unsigned, test.quad, 0, 2)
		source += fmt.Sprintf("\tWORD $%#08x\n", word)
	}
	source += "\tRET\n"
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"rawConvertFloat32All": {Name: "rawConvertFloat32All", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"sitofp <2 x i32>", "uitofp <4 x i32>", "fptosi <2 x float>", "fptoui <4 x float>"} {
		if !strings.Contains(ir, want) {
			t.Fatalf("raw NEON VCVT all operations omitted %q:\n%s", want, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-raw-neon-vcvt-all.ll", "arm-raw-neon-vcvt-all.o", ir)
}

func TestARMRawNEONVCVTFloat32RejectsReservedForms(t *testing.T) {
	for _, word := range []uint32{
		encodeARMRawNEONConvertFloat32(true, false, false, 0, 0) &^ (uint32(31) << 7),
		encodeARMRawNEONConvertFloat32(true, false, true, 0, 0) | 1<<12,
		encodeARMRawNEONConvertFloat32(true, false, true, 0, 0) | 1,
		encodeARMRawNEONConvertFloat32(true, false, false, 0, 0) | 1<<4,
	} {
		if _, ok := decodeARMRawNEONConvertFloat32(word); ok {
			t.Fatalf("NEON VCVT decoder accepted reserved encoding %#08x", word)
		}
	}
}
