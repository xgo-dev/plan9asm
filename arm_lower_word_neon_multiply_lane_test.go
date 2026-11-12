package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARMRawNEONMultiplyLane(floating, quad bool, elementBits, destination, lhs, scalar, lane int) uint32 {
	word := uint32(0xf2800840 | (destination&15)<<12 | (lhs&15)<<16)
	if floating {
		word |= 1 << 8
	}
	if quad {
		word |= 1 << 24
	}
	word |= uint32(map[int]int{16: 1, 32: 2}[elementBits]) << 20
	word |= uint32(destination/16) << 22
	word |= uint32(lhs/16) << 7
	if elementBits == 16 {
		word |= uint32(scalar & 7)
		word |= uint32(lane&1) << 3
		word |= uint32(lane/2) << 5
	} else {
		word |= uint32(scalar & 15)
		word |= uint32(lane) << 5
	}
	return word
}

func TestTranslateARMRawNEONVMULLaneGoDSPRegression(t *testing.T) {
	const source = `TEXT rawMultiplyLane(SB), $0-0
	WORD $0xf3a22940 // vmul.f32 q1, q1, d0[0]
	RET
`
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"rawMultiplyLane": {Name: "rawMultiplyLane", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"extractelement <2 x float>", "fmul <4 x float>", `"target-features"="+neon"`} {
		if !strings.Contains(ir, want) {
			t.Fatalf("raw NEON VMUL-by-lane IR omitted %q:\n%s", want, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-raw-neon-vmul-lane.ll", "arm-raw-neon-vmul-lane.o", ir)
}

func TestARMRawNEONVMULLaneDecoderCoversEveryEncodingField(t *testing.T) {
	count := 0
	for _, floating := range []bool{false, true} {
		for _, quad := range []bool{false, true} {
			step := 1
			if quad {
				step = 2
			}
			for _, elementBits := range []int{16, 32} {
				scalarRegisters := 8
				lanes := 4
				if elementBits == 32 {
					scalarRegisters = 16
					lanes = 2
				}
				for destination := 0; destination < 32; destination += step {
					for lhs := 0; lhs < 32; lhs += step {
						for scalar := 0; scalar < scalarRegisters; scalar++ {
							for lane := 0; lane < lanes; lane++ {
								word := encodeARMRawNEONMultiplyLane(floating, quad, elementBits, destination, lhs, scalar, lane)
								got, ok := decodeARMRawNEONMultiplyLane(word)
								if !ok || got.floating != floating || got.quad != quad || got.elementBits != elementBits || got.destination != destination || got.lhs != lhs || got.scalar != scalar || got.lane != lane {
									t.Fatalf("decoded NEON VMUL-by-lane %#08x as %+v, ok=%v", word, got, ok)
								}
								count++
							}
						}
					}
				}
			}
		}
	}
	if count != 163840 {
		t.Fatalf("covered %d NEON VMUL-by-lane encodings, want 163840", count)
	}
}

func TestTranslateARMRawNEONVMULLaneAllFormats(t *testing.T) {
	source := "TEXT rawMultiplyLaneAll(SB), $0-0\n"
	for _, test := range []struct {
		floating    bool
		quad        bool
		elementBits int
	}{
		{false, false, 16}, {false, true, 16}, {false, false, 32}, {false, true, 32},
		{true, false, 16}, {true, true, 16}, {true, false, 32}, {true, true, 32},
	} {
		word := encodeARMRawNEONMultiplyLane(test.floating, test.quad, test.elementBits, 0, 2, 1, 1)
		source += fmt.Sprintf("\tWORD $%#08x\n", word)
	}
	source += "\tRET\n"
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"rawMultiplyLaneAll": {Name: "rawMultiplyLaneAll", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"mul <4 x i16>", "mul <4 x i32>", "fmul <4 x half>", "fmul <4 x float>", "+fullfp16", "+neon"} {
		if !strings.Contains(ir, want) {
			t.Fatalf("raw NEON VMUL-by-lane formats omitted %q:\n%s", want, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-raw-neon-vmul-lane-all.ll", "arm-raw-neon-vmul-lane-all.o", ir)
}

func TestARMRawNEONVMULLaneRejectsReservedForms(t *testing.T) {
	for _, word := range []uint32{
		encodeARMRawNEONMultiplyLane(false, false, 16, 0, 0, 0, 0) &^ (uint32(3) << 20),
		encodeARMRawNEONMultiplyLane(false, true, 16, 0, 0, 0, 0) | 1<<12,
		encodeARMRawNEONMultiplyLane(false, true, 16, 0, 0, 0, 0) | 1<<16,
		encodeARMRawNEONMultiplyLane(false, false, 16, 0, 0, 0, 0) | 1<<4,
	} {
		if _, ok := decodeARMRawNEONMultiplyLane(word); ok {
			t.Fatalf("NEON VMUL-by-lane decoder accepted reserved encoding %#08x", word)
		}
	}
}
