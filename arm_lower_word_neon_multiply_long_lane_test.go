package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARMRawNEONMultiplyLongLane(unsigned bool, elementBits, destination, lhs, scalar, lane int) uint32 {
	word := uint32(0xf2800a40 | (destination&15)<<12 | (lhs&15)<<16)
	if unsigned {
		word |= 1 << 24
	}
	if elementBits == 16 {
		word |= 1 << 20
		word |= uint32(scalar & 7)
		word |= uint32(lane&1) << 3
		word |= uint32(lane/2) << 5
	} else {
		word |= 2 << 20
		word |= uint32(scalar & 15)
		word |= uint32(lane) << 5
	}
	word |= uint32(destination/16) << 22
	word |= uint32(lhs/16) << 7
	return word
}

func encodeARMRawNEONWideningMultiplyLane(kind string, unsigned bool, elementBits, destination, lhs, scalar, lane int) uint32 {
	word := encodeARMRawNEONMultiplyLongLane(unsigned, elementBits, destination, lhs, scalar, lane)
	switch kind {
	case "mla":
		return word&^0xf00 | 0x200
	case "mls":
		return word&^0xf00 | 0x600
	default:
		return word
	}
}

func TestARMRawNEONWideningMultiplyLaneAccumulateLLVM22Forms(t *testing.T) {
	for _, test := range []struct {
		word        uint32
		kind        string
		unsigned    bool
		elementBits int
		destination int
		lhs         int
		scalar      int
		lane        int
	}{
		{0xf2910242, "mla", false, 16, 0, 1, 2, 0},
		{0xf3910242, "mla", true, 16, 0, 1, 2, 0},
		{0xf2a10242, "mla", false, 32, 0, 1, 2, 0},
		{0xf3a7a262, "mla", true, 32, 10, 7, 2, 1},
		{0xf2910642, "mls", false, 16, 0, 1, 2, 0},
		{0xf3910642, "mls", true, 16, 0, 1, 2, 0},
		{0xf2a10642, "mls", false, 32, 0, 1, 2, 0},
		{0xf3a10642, "mls", true, 32, 0, 1, 2, 0},
	} {
		got, ok := decodeARMRawNEONMultiplyLongLane(test.word)
		if !ok || got.kind != test.kind || got.unsigned != test.unsigned ||
			got.elementBits != test.elementBits || got.destination != test.destination ||
			got.lhs != test.lhs || got.scalar != test.scalar || got.lane != test.lane {
			t.Fatalf("LLVM 22 encoding %#08x decoded as %+v, ok=%v", test.word, got, ok)
		}
		if encoded := encodeARMRawNEONWideningMultiplyLane(
			test.kind, test.unsigned, test.elementBits, test.destination,
			test.lhs, test.scalar, test.lane,
		); encoded != test.word {
			t.Fatalf("encoded %+v as %#08x, want %#08x", test, encoded, test.word)
		}
	}
}

func TestTranslateARMRawNEONWideningMultiplyLaneAccumulateLLVM22(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawWideningMultiplyAccumulate(SB), $0-0\n")
	for _, kind := range []string{"mla", "mls"} {
		for _, unsigned := range []bool{false, true} {
			for _, elementBits := range []int{16, 32} {
				word := encodeARMRawNEONWideningMultiplyLane(
					kind, unsigned, elementBits, 10, 2, 0, 1,
				)
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
		Sigs: map[string]FuncSig{"rawWideningMultiplyAccumulate": {Name: "rawWideningMultiplyAccumulate", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"mul <4 x i32>", "mul <2 x i64>", "add <4 x i32>", "sub <2 x i64>"} {
		if !strings.Contains(ir, fragment) {
			t.Fatalf("raw VMLAL/VMLSL omitted %q:\n%s", fragment, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, triple, "arm-raw-neon-vmlal-vmlsl.ll", "arm-raw-neon-vmlal-vmlsl.o", ir)
}

func TestARMRawNEONMultiplyLongLaneLLVM22Forms(t *testing.T) {
	for _, test := range []struct {
		word        uint32
		unsigned    bool
		elementBits int
		destination int
		lhs         int
		scalar      int
		lane        int
	}{
		{0xf2910a42, false, 16, 0, 1, 2, 0},
		{0xf2dfeaef, false, 16, 30, 31, 7, 3},
		{0xf3910a42, true, 16, 0, 1, 2, 0},
		{0xf3dfeaef, true, 16, 30, 31, 7, 3},
		{0xf2a10a42, false, 32, 0, 1, 2, 0},
		{0xf2efeaef, false, 32, 30, 31, 15, 1},
		{0xf3a10a42, true, 32, 0, 1, 2, 0},
		{0xf3efeaef, true, 32, 30, 31, 15, 1},
		{0xf3a0aa60, true, 32, 10, 0, 0, 1},
	} {
		got, ok := decodeARMRawNEONMultiplyLongLane(test.word)
		if !ok || got.unsigned != test.unsigned || got.elementBits != test.elementBits ||
			got.destination != test.destination || got.lhs != test.lhs ||
			got.scalar != test.scalar || got.lane != test.lane {
			t.Fatalf("LLVM 22 VMULL lane encoding %#08x decoded as %+v, ok=%v", test.word, got, ok)
		}
		if encoded := encodeARMRawNEONMultiplyLongLane(
			test.unsigned, test.elementBits, test.destination, test.lhs, test.scalar, test.lane,
		); encoded != test.word {
			t.Fatalf("encoded %+v as %#08x, want %#08x", test, encoded, test.word)
		}
	}
}

func TestARMRawNEONMultiplyLongLaneAllFields(t *testing.T) {
	count := 0
	for _, kind := range []string{"mul", "mla", "mls"} {
		for _, unsigned := range []bool{false, true} {
			for _, elementBits := range []int{16, 32} {
				scalarRegisters, lanes := 8, 4
				if elementBits == 32 {
					scalarRegisters, lanes = 16, 2
				}
				for destination := 0; destination < 32; destination += 2 {
					for lhs := 0; lhs < 32; lhs++ {
						for scalar := 0; scalar < scalarRegisters; scalar++ {
							for lane := 0; lane < lanes; lane++ {
								word := encodeARMRawNEONWideningMultiplyLane(
									kind, unsigned, elementBits, destination, lhs, scalar, lane,
								)
								got, ok := decodeARMRawNEONMultiplyLongLane(word)
								if !ok || got.kind != kind || got.unsigned != unsigned || got.elementBits != elementBits ||
									got.destination != destination || got.lhs != lhs ||
									got.scalar != scalar || got.lane != lane {
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
	if count != 196608 {
		t.Fatalf("covered %d VMULL/VMLAL/VMLSL lane forms, want 196608", count)
	}
}

func TestTranslateARMRawNEONMultiplyLongLaneAllFormatsLLVM22(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawVMULLLane(SB), $0-0\n")
	for _, unsigned := range []bool{false, true} {
		for _, elementBits := range []int{16, 32} {
			word := encodeARMRawNEONMultiplyLongLane(unsigned, elementBits, 10, 2, 0, 1)
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
		Sigs: map[string]FuncSig{"rawVMULLLane": {Name: "rawVMULLLane", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"sext <4 x i16>", "zext <4 x i16>", "mul <4 x i32>",
		"sext <2 x i32>", "zext <2 x i32>", "mul <2 x i64>",
	} {
		if !strings.Contains(ir, fragment) {
			t.Fatalf("raw VMULL lane omitted %q:\n%s", fragment, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, triple, "arm-raw-neon-vmull-lane.ll", "arm-raw-neon-vmull-lane.o", ir)
}

func TestARMRawNEONMultiplyLongLaneRejectsReservedForms(t *testing.T) {
	base := encodeARMRawNEONMultiplyLongLane(true, 32, 0, 0, 0, 0)
	for _, word := range []uint32{
		base | 1<<12,
		base &^ (3 << 20),
		base | 1<<4,
		base ^ 1<<9,
	} {
		if _, ok := decodeARMRawNEONMultiplyLongLane(word); ok {
			t.Fatalf("accepted reserved VMULL lane encoding %#08x", word)
		}
	}
}
