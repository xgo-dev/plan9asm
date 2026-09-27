package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

var x86RawCompressForms = []struct {
	opcode    int
	widthBit  int
	op        Op
	laneBytes int
}{
	{0x63, 0, "VPCOMPRESSB", 1},
	{0x63, 1, "VPCOMPRESSW", 2},
	{0x8a, 0, "VCOMPRESSPS", 4},
	{0x8a, 1, "VCOMPRESSPD", 8},
	{0x8b, 0, "VPCOMPRESSD", 4},
	{0x8b, 1, "VPCOMPRESSQ", 8},
}

func encodeX86RawCompress(opcode, widthBit, vectorBits, mask int, zeroing, memory bool) []byte {
	p1 := byte(0x7d) // EVEX.vvvv is unused, pp = 66.
	if widthBit != 0 {
		p1 |= 0x80
	}
	p2 := byte(vectorBits<<5 | 0x08 | mask)
	if zeroing {
		p2 |= 0x80
	}
	modRM := byte(0xd3) // source register 2, destination register 3.
	if memory {
		modRM = 0x50 // source register 2, disp8(AX) destination.
	}
	code := []byte{0x62, 0xf2, p1, p2, byte(opcode), modRM}
	if memory {
		code = append(code, 1)
	}
	return code
}

func TestDecodeX86RawCompressSeBiShogunRegression(t *testing.T) {
	// Go disassembles the bytes as VCOMPRESSPS Z0, K1, 0(SI)(R9*4).
	code := []byte{0x62, 0xb2, 0x7d, 0x49, 0x8a, 0x04, 0x8e, 0xc3}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "compressBitsFloat32 AVX512 VCOMPRESSPS", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || decoded[0].Op != "VCOMPRESSPS" ||
		decoded[0].Args[0].Reg != "Z0" || decoded[0].Args[1].Reg != "K1" {
		t.Fatalf("decoded %x as %#v", code, decoded)
	}
}

func TestDecodeX86RawCompressCompleteGoForms(t *testing.T) {
	if len(x86RawCompressForms) != len(amd64PackedCompressLaneBits) {
		t.Fatalf("raw/lower compress grammar rows = %d/%d", len(x86RawCompressForms), len(amd64PackedCompressLaneBits))
	}
	for _, form := range x86RawCompressForms {
		for vectorBits, vector := range []string{"X", "Y", "Z"} {
			for _, variant := range []struct {
				name    string
				mask    int
				zeroing bool
				memory  bool
			}{
				{name: "register"},
				{name: "masked register", mask: 3},
				{name: "zeroing register", mask: 7, zeroing: true},
				{name: "memory", memory: true},
				{name: "masked memory", mask: 1, memory: true},
			} {
				name := fmt.Sprintf("%s/%s/%s", form.op, vector, variant.name)
				t.Run(name, func(t *testing.T) {
					code := encodeX86RawCompress(form.opcode, form.widthBit, vectorBits, variant.mask, variant.zeroing, variant.memory)
					got, length, ok, err := decodedX86PackedCompressInstruction(code, 64)
					if err != nil || !ok || length != len(code) {
						t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
					}
					wantOp := form.op
					if variant.zeroing {
						wantOp += ".Z"
					}
					if got.Op != wantOp || got.Args[0].String() != vector+"2" ||
						!variant.memory && got.Args[len(got.Args)-1].String() != vector+"3" ||
						variant.memory && got.Args[len(got.Args)-1].String() != fmt.Sprintf("%d(AX)", form.laneBytes) ||
						len(got.Args) != 2+map[bool]int{true: 1}[variant.mask != 0] {
						t.Fatalf("decode %x = %+v, want %s", code, got, wantOp)
					}
				})
			}
		}
	}
}

func TestDecodeX86RawCompressRejectsInvalidForms(t *testing.T) {
	base := encodeX86RawCompress(0x8a, 0, 2, 0, false, false)
	for _, mutate := range []func([]byte){
		func(code []byte) { code[3] |= 0x80 },  // zeroing without mask
		func(code []byte) { code[3] |= 0x60 },  // reserved vector length
		func(code []byte) { code[3] |= 0x10 },  // broadcast unavailable
		func(code []byte) { code[2] &^= 0x08 }, // EVEX.vvvv is reserved
	} {
		code := append([]byte(nil), base...)
		mutate(code)
		if _, _, ok, err := decodedX86PackedCompressInstruction(code, 64); !ok || err == nil {
			t.Fatalf("invalid encoding %x returned ok=%v err=%v", code, ok, err)
		}
	}
	if _, _, ok, err := decodedX86PackedCompressInstruction(encodeX86RawCompress(0x8a, 0, 2, 1, false, false), 32); !ok || err == nil {
		t.Fatalf("accepted 386 masked compress: ok=%v err=%v", ok, err)
	}
}

func TestTranslateX86RawCompressLLVM22Objects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		goarch string
		triple string
	}{
		{"amd64", "x86_64-apple-darwin"},
		{"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-pc-windows-msvc"},
		{"386", "i386-unknown-linux-gnu"},
		{"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT rawCompress(SB),$0-0\n")
			for _, form := range x86RawCompressForms {
				for _, memory := range []bool{false, true} {
					mask := 1
					if target.goarch == "386" {
						mask = 0
					}
					code := encodeX86RawCompress(form.opcode, form.widthBit, 0, mask, false, memory)
					for _, value := range code {
						fmt.Fprintf(&source, "\tBYTE $0x%02x\n", value)
					}
				}
			}
			source.WriteString("\tRET\n")
			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"rawCompress": {Name: "rawCompress", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-compress.ll", "raw-compress.o", ir)
		})
	}
}
