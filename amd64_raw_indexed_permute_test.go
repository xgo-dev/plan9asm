package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

var x86RawIndexedPermuteForms = []struct {
	opcode    int
	widthBit  int
	op        Op
	laneBytes int
}{
	{0x75, 0, "VPERMI2B", 1}, {0x75, 1, "VPERMI2W", 2},
	{0x76, 0, "VPERMI2D", 4}, {0x76, 1, "VPERMI2Q", 8},
	{0x77, 0, "VPERMI2PS", 4}, {0x77, 1, "VPERMI2PD", 8},
	{0x7d, 0, "VPERMT2B", 1}, {0x7d, 1, "VPERMT2W", 2},
	{0x7e, 0, "VPERMT2D", 4}, {0x7e, 1, "VPERMT2Q", 8},
	{0x7f, 0, "VPERMT2PS", 4}, {0x7f, 1, "VPERMT2PD", 8},
}

func TestDecodeX86RawIndexedPermuteSeBiShogunRegression(t *testing.T) {
	// Go disassembles these bytes as VPERMT2W Y18, Y19, Y21.
	code := []byte{0x62, 0xa2, 0xe5, 0x20, 0x7d, 0xea, 0xc3}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "validUTF8 AVX512 VPERMT2W", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || decoded[0].Op != "VPERMT2W" ||
		decoded[0].Args[0].Reg != "Y18" || decoded[0].Args[1].Reg != "Y19" ||
		decoded[0].Args[2].Reg != "Y21" {
		t.Fatalf("decoded %x as %#v", code, decoded)
	}
}

func encodeX86RawIndexedPermute(opcode, widthBit, vectorBits, mask int, broadcast, memory bool) []byte {
	p1 := byte(0x75) // EVEX.vvvv = vector register 1, pp = 66.
	if widthBit != 0 {
		p1 |= 0x80
	}
	p2 := byte(vectorBits<<5 | 0x08 | mask)
	if broadcast {
		p2 |= 0x10
	}
	modRM := byte(0xd3) // first source register 3, destination register 2.
	if memory {
		modRM = 0x50 // disp8(AX), destination register 2.
	}
	code := []byte{0x62, 0xf2, p1, p2, byte(opcode), modRM}
	if memory {
		code = append(code, 1)
	}
	return code
}

func TestDecodeX86RawIndexedPermuteCompleteGoForms(t *testing.T) {
	if len(x86RawIndexedPermuteForms) != 12 || len(amd64IndexedPermuteSpecs) != 14 {
		t.Fatalf("raw/indexed-permute grammar has %d/%d rows, want 12/14", len(x86RawIndexedPermuteForms), len(amd64IndexedPermuteSpecs))
	}
	for _, form := range x86RawIndexedPermuteForms {
		for vectorBits, vector := range []string{"X", "Y", "Z"} {
			for _, variant := range []struct {
				name      string
				mask      int
				broadcast bool
				memory    bool
			}{
				{name: "register"},
				{name: "masked register", mask: 3},
				{name: "memory", memory: true},
				{name: "masked memory", mask: 7, memory: true},
				{name: "broadcast memory", broadcast: true, memory: true},
			} {
				if variant.broadcast && form.laneBytes < 4 {
					continue
				}
				name := fmt.Sprintf("%s/%s/%s", form.op, vector, variant.name)
				t.Run(name, func(t *testing.T) {
					code := encodeX86RawIndexedPermute(form.opcode, form.widthBit, vectorBits, variant.mask, variant.broadcast, variant.memory)
					got, length, ok, err := decodedX86IndexedPermuteInstruction(code, 64)
					if err != nil || !ok || length != len(code) {
						t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
					}
					wantOp := form.op
					if variant.broadcast {
						wantOp += ".BCST"
					}
					if got.Op != wantOp || got.Args[1].String() != vector+"1" ||
						got.Args[len(got.Args)-1].String() != vector+"2" ||
						len(got.Args) != 3+map[bool]int{true: 1}[variant.mask != 0] {
						t.Fatalf("decode %x = %+v, want %s", code, got, wantOp)
					}
				})
			}
		}
	}
}

func TestDecodeX86RawIndexedPermuteRIPLiteral(t *testing.T) {
	for _, form := range x86RawIndexedPermuteForms {
		for _, broadcast := range []bool{false, true} {
			if broadcast && form.laneBytes < 4 {
				continue
			}
			code := encodeX86RawIndexedPermute(form.opcode, form.widthBit, 2, 1, broadcast, false)
			code[5] = 0x15 // RIP-relative first source.
			code = append(code, 1, 0, 0, 0, 0xc3)
			literalWidth := 64
			if broadcast {
				literalWidth = form.laneBytes
			}
			for index := 0; index < literalWidth; index++ {
				code = append(code, byte(index+1))
			}
			name := fmt.Sprintf("%s/broadcast%t", form.op, broadcast)
			t.Run(name, func(t *testing.T) {
				got, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
				if err != nil {
					t.Fatal(err)
				}
				wantOp := form.op
				if broadcast {
					wantOp += ".BCST"
				}
				if len(got) != 2 || !got[0].x86RIPLiteral ||
					len(got[0].x86RIPLiteralData) != literalWidth || got[0].Op != wantOp {
					t.Fatalf("decode %x = %+v", code, got)
				}
			})
		}
	}
}

func TestTranslateX86RawIndexedPermuteLLVM22Objects(t *testing.T) {
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
			source.WriteString("TEXT rawIndexedPermute(SB),$0-0\n")
			for _, opcode := range []int{0x75, 0x76, 0x77, 0x7d, 0x7e, 0x7f} {
				for _, widthBit := range []int{0, 1} {
					code := encodeX86RawIndexedPermute(opcode, widthBit, 0, 0, false, false)
					for _, value := range code {
						fmt.Fprintf(&source, "\tBYTE $0x%02x\n", value)
					}
					if opcode == 0x75 || opcode == 0x7d {
						continue
					}
					mask := 3
					if target.goarch == "386" {
						mask = 0
					}
					code = encodeX86RawIndexedPermute(opcode, widthBit, 0, mask, true, true)
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
				Sigs: map[string]FuncSig{"rawIndexedPermute": {Name: "rawIndexedPermute", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-indexed-permute.ll", "raw-indexed-permute.o", ir)
		})
	}
}
