package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARMRawNEONEOR(quad bool, destination, lhs, rhs int) uint32 {
	word := uint32(0xf3000110 | (destination&15)<<12 | (lhs&15)<<16 | rhs&15)
	word |= uint32(destination/16) << 22
	word |= uint32(lhs/16) << 7
	word |= uint32(rhs/16) << 5
	if quad {
		word |= 1 << 6
	}
	return word
}

func encodeARMRawNEONORR(quad bool, destination, lhs, rhs int) uint32 {
	return encodeARMRawNEONEOR(quad, destination, lhs, rhs) ^ 0x01200000
}

func encodeARMRawNEONBitwise(operation string, quad bool, destination, lhs, rhs int) uint32 {
	word := encodeARMRawNEONEOR(quad, destination, lhs, rhs)
	switch operation {
	case "and":
		return word ^ 0x01000000
	case "bic":
		return word ^ 0x01100000
	case "or":
		return word ^ 0x01200000
	case "orn":
		return word ^ 0x01300000
	default:
		return word
	}
}

func TestARMRawNEONBitwiseAllLLVM22Forms(t *testing.T) {
	for _, test := range []struct {
		operation string
		base      uint32
	}{
		{"and", 0xf2010112},
		{"bic", 0xf2110112},
		{"or", 0xf2210112},
		{"orn", 0xf2310112},
		{"xor", 0xf3010112},
	} {
		for _, quad := range []bool{false, true} {
			step := 1
			if quad {
				step = 2
			}
			for destination := 0; destination < 32; destination += step {
				for lhs := 0; lhs < 32; lhs += step {
					for rhs := 0; rhs < 32; rhs += step {
						word := encodeARMRawNEONBitwise(
							test.operation, quad, destination, lhs, rhs,
						)
						got, ok := decodeARMRawNEONBitwise(word)
						if !ok || got.operation != test.operation || got.quad != quad ||
							got.destination != destination || got.lhs != lhs || got.rhs != rhs {
							t.Fatalf("encoding %#08x decoded as %+v, ok=%v", word, got, ok)
						}
					}
				}
			}
		}
		if encoded := encodeARMRawNEONBitwise(test.operation, false, 0, 1, 2); encoded != test.base {
			t.Fatalf("encoded %s as %#08x, want %#08x", test.operation, encoded, test.base)
		}
	}
}

func TestTranslateARMRawNEONBitwiseAllLLVM22(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawBitwise(SB), $0-0\n")
	for _, operation := range []string{"and", "bic", "or", "orn", "xor"} {
		for _, quad := range []bool{false, true} {
			word := encodeARMRawNEONBitwise(operation, quad, 0, 2, 4)
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
		Sigs: map[string]FuncSig{"rawBitwise": {Name: "rawBitwise", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"and <1 x i64>", "and <2 x i64>",
		"or <1 x i64>", "or <2 x i64>",
		"xor <1 x i64>", "xor <2 x i64>",
	} {
		if !strings.Contains(ir, fragment) {
			t.Fatalf("bitwise IR omitted %q:\n%s", fragment, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, triple, "arm-raw-neon-bitwise-all.ll", "arm-raw-neon-bitwise-all.o", ir)
}

func TestARMRawNEONORRLLVM22Forms(t *testing.T) {
	for _, test := range []struct {
		word        uint32
		quad        bool
		destination int
		lhs         int
		rhs         int
	}{
		{0xf2210112, false, 0, 1, 2},
		{0xf2220154, true, 0, 2, 4},
		{0xf2208150, true, 8, 0, 0},
		{0xf260f19f, false, 31, 16, 15},
		{0xf260e1fc, true, 30, 16, 28},
	} {
		got, ok := decodeARMRawNEONBitwise(test.word)
		if !ok || got.operation != "or" || got.quad != test.quad ||
			got.destination != test.destination || got.lhs != test.lhs || got.rhs != test.rhs {
			t.Fatalf("LLVM 22 VORR encoding %#08x decoded as %+v, ok=%v", test.word, got, ok)
		}
		if encoded := encodeARMRawNEONORR(test.quad, test.destination, test.lhs, test.rhs); encoded != test.word {
			t.Fatalf("encoded VORR %+v as %#08x, want %#08x", test, encoded, test.word)
		}
	}
}

func TestTranslateARMRawNEONORRWireGuardRegression(t *testing.T) {
	const source = `TEXT rawORR(SB), $0-0
	WORD $0xf2208150 // vmov q4,q0, encoded as vorr q4,q0,q0
	WORD $0xf2210112 // vorr d0,d1,d2
	RET
`
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf",
		Sigs: map[string]FuncSig{"rawORR": {Name: "rawORR", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"or <2 x i64>", "or <1 x i64>"} {
		if !strings.Contains(ir, fragment) {
			t.Fatalf("raw VORR omitted %q:\n%s", fragment, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-raw-neon-vorr.ll", "arm-raw-neon-vorr.o", ir)
}

func TestARMRawNEONORRAllRegisterFields(t *testing.T) {
	count := 0
	for _, quad := range []bool{false, true} {
		step := 1
		if quad {
			step = 2
		}
		for destination := 0; destination < 32; destination += step {
			for lhs := 0; lhs < 32; lhs += step {
				for rhs := 0; rhs < 32; rhs += step {
					word := encodeARMRawNEONORR(quad, destination, lhs, rhs)
					got, ok := decodeARMRawNEONBitwise(word)
					if !ok || got.operation != "or" || got.quad != quad ||
						got.destination != destination || got.lhs != lhs || got.rhs != rhs {
						t.Fatalf("encoding %#08x decoded as %+v, ok=%v", word, got, ok)
					}
					count++
				}
			}
		}
	}
	if count != 36864 {
		t.Fatalf("covered %d VORR forms, want 36864", count)
	}
}

func TestTranslateARMRawNEONVEORPionTransportRegression(t *testing.T) {
	const source = `TEXT rawXor(SB), $0-0
	WORD $0xF3004154 // veor q2, q0, q2
	WORD $0xF3026156 // veor q3, q1, q3
	WORD $0xF3002152 // veor q1, q0, q1
	WORD $0xF3001111 // veor d1, d0, d1
	RET
`
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"rawXor": {Name: "rawXor", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"xor <2 x i64>", "xor <1 x i64>", `"target-features"="+neon"`} {
		if !strings.Contains(ir, want) {
			t.Fatalf("raw NEON VEOR IR omitted %q:\n%s", want, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-raw-neon-veor.ll", "arm-raw-neon-veor.o", ir)
}

func TestARMRawNEONVEORDecoderCoversEveryEncodingField(t *testing.T) {
	count := 0
	for _, quad := range []bool{false, true} {
		step := 1
		if quad {
			step = 2
		}
		for destination := 0; destination < 32; destination += step {
			for lhs := 0; lhs < 32; lhs += step {
				for rhs := 0; rhs < 32; rhs += step {
					word := encodeARMRawNEONEOR(quad, destination, lhs, rhs)
					got, ok := decodeARMRawNEONEOR(word)
					if !ok || got.quad != quad || got.destination != destination || got.lhs != lhs || got.rhs != rhs {
						t.Fatalf("decoded NEON VEOR %#08x as %+v, ok=%v", word, got, ok)
					}
					count++
				}
			}
		}
	}
	if count != 36864 {
		t.Fatalf("covered %d NEON VEOR encodings, want 36864", count)
	}
}

func TestARMRawNEONVEORRejectsReservedForms(t *testing.T) {
	for _, word := range []uint32{
		encodeARMRawNEONEOR(true, 0, 0, 0) | 1<<12,
		encodeARMRawNEONEOR(true, 0, 0, 0) | 1<<16,
		encodeARMRawNEONEOR(true, 0, 0, 0) | 1,
		encodeARMRawNEONEOR(false, 0, 0, 0) ^ 1<<8,
	} {
		if got, ok := decodeARMRawNEONEOR(word); ok {
			t.Fatalf("NEON VEOR decoder accepted reserved encoding %#08x as %s", word, fmt.Sprint(got))
		}
	}
}
