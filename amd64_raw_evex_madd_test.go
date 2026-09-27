package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeX86RawEVEXPackedMADD(op Op, width, mask, destination, first, second int, zeroing, memory bool) []byte {
	opcode, opcodeMap := byte(0xf5), byte(1)
	if op == "VPMADDUBSW" {
		opcode, opcodeMap = 0x04, 2
	}
	p0 := byte((1-(destination>>3)&1)<<7 | (1-(first>>4)&1)<<6 |
		(1-(first>>3)&1)<<5 | (1-(destination>>4)&1)<<4 | int(opcodeMap))
	p1 := byte(((^second)&15)<<3 | 0x05)
	p2 := byte(width<<5 | (1-((second>>4)&1))<<3 | mask)
	if zeroing {
		p2 |= 0x80
	}
	modRM := byte(0xc0 | (destination&7)<<3 | first&7)
	if memory {
		modRM = byte(0x40 | (destination&7)<<3)
		p0 = byte((1-(destination>>3)&1)<<7 | 0x60 | (1-(destination>>4)&1)<<4 | int(opcodeMap))
	}
	code := []byte{0x62, p0, p1, p2, opcode, modRM}
	if memory {
		code = append(code, 1)
	}
	return code
}

func TestDecodeX86RawEVEXMADDSeBiShogunRegression(t *testing.T) {
	// Go's assembler disassembles these bytes as VPMADDUBSW Z1, Z5, Z1.
	code := []byte{0x62, 0xf2, 0x55, 0x48, 0x04, 0xc9, 0xc3}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "mulInt8 AVX512 VPMADDUBSW", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || decoded[0].Op != "VPMADDUBSW" ||
		decoded[0].Args[0].Reg != "Z1" || decoded[0].Args[1].Reg != "Z5" ||
		decoded[0].Args[2].Reg != "Z1" {
		t.Fatalf("decoded %x as %#v", code, decoded)
	}
}

func TestDecodeX86RawEVEXPackedMADDCompleteGoForms(t *testing.T) {
	for _, op := range []Op{"VPMADDWD", "VPMADDUBSW"} {
		for width := 0; width < 3; width++ {
			vector := [...]string{"X", "Y", "Z"}[width]
			for _, form := range []struct {
				name        string
				mask        int
				zeroing     bool
				memory      bool
				destination int
				first       int
				second      int
			}{
				{name: "register", destination: 2, first: 3, second: 4},
				{name: "high registers", destination: 18, first: 19, second: 20},
				{name: "masked", mask: 3, destination: 2, first: 3, second: 4},
				{name: "zeroing", mask: 7, zeroing: true, destination: 2, first: 3, second: 4},
				{name: "memory", memory: true, destination: 2, second: 4},
				{name: "zeroing memory", memory: true, mask: 5, zeroing: true, destination: 2, second: 4},
			} {
				name := fmt.Sprintf("%s/%s/%s", op, vector, form.name)
				t.Run(name, func(t *testing.T) {
					code := encodeX86RawEVEXPackedMADD(
						op, width, form.mask, form.destination, form.first, form.second, form.zeroing, form.memory,
					)
					got, length, ok, err := decodedX86EVEXPackedMADDInstruction(code, 64)
					if err != nil || !ok || length != len(code) {
						t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
					}
					wantOp := op
					if form.zeroing {
						wantOp += ".Z"
					}
					if got.Op != wantOp || got.Args[1].String() != fmt.Sprintf("%s%d", vector, form.second) ||
						got.Args[len(got.Args)-1].String() != fmt.Sprintf("%s%d", vector, form.destination) {
						t.Fatalf("decode %x = %+v, want %s", code, got, wantOp)
					}
					if !form.memory && got.Args[0].String() != fmt.Sprintf("%s%d", vector, form.first) {
						t.Fatalf("decode %x first source = %s", code, got.Args[0])
					}
				})
			}
		}
	}
}

func TestDecodeX86RawEVEXPackedMADDRIPLiteral(t *testing.T) {
	for _, op := range []Op{"VPMADDWD", "VPMADDUBSW"} {
		for width := 0; width < 3; width++ {
			code := encodeX86RawEVEXPackedMADD(op, width, 1, 2, 0, 4, false, false)
			code[5] = 0x15 // RIP-relative first source, destination 2.
			code = append(code, 1, 0, 0, 0, 0xc3)
			literalWidth := 16 << width
			for index := 0; index < literalWidth; index++ {
				code = append(code, byte(index+1))
			}
			name := fmt.Sprintf("%s/width%d", op, width)
			t.Run(name, func(t *testing.T) {
				got, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
				if err != nil {
					t.Fatal(err)
				}
				if len(got) != 2 || !got[0].x86RIPLiteral || len(got[0].x86RIPLiteralData) != literalWidth || got[0].Op != op {
					t.Fatalf("decode %x = %+v", code, got)
				}
			})
		}
	}
}

func TestDecodeX86RawEVEXPackedMADDRejectsInvalidForms(t *testing.T) {
	base := encodeX86RawEVEXPackedMADD("VPMADDUBSW", 2, 0, 2, 3, 4, false, false)
	for _, mutate := range []func([]byte){
		func(code []byte) { code[2] |= 0x80 }, // EVEX.W1
		func(code []byte) { code[3] |= 0x10 }, // unsupported broadcast
		func(code []byte) { code[3] |= 0x80 }, // zeroing without mask
		func(code []byte) { code[3] |= 0x20 }, // reserved vector length
	} {
		code := append([]byte(nil), base...)
		mutate(code)
		if _, _, ok, err := decodedX86EVEXPackedMADDInstruction(code, 64); !ok || err == nil {
			t.Fatalf("invalid encoding %x returned ok=%v err=%v", code, ok, err)
		}
	}
}

func TestTranslateX86RawEVEXPackedMADDLLVM22Objects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name, goarch, triple string
	}{
		{"darwin-amd64", "amd64", "x86_64-apple-darwin"},
		{"linux-amd64", "amd64", "x86_64-unknown-linux-gnu"},
		{"windows-amd64", "amd64", "x86_64-pc-windows-msvc"},
		{"linux-386", "386", "i386-unknown-linux-gnu"},
		{"windows-386", "386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT rawEVEXPackedMADD(SB),$0-0\n")
			for _, op := range []Op{"VPMADDWD", "VPMADDUBSW"} {
				for width := 0; width < 3; width++ {
					for _, memory := range []bool{false, true} {
						code := encodeX86RawEVEXPackedMADD(op, width, 0, 2, 3, 4, false, memory)
						for _, value := range code {
							fmt.Fprintf(&source, "\tBYTE $0x%02x\n", value)
						}
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
				Sigs: map[string]FuncSig{"rawEVEXPackedMADD": {Name: "rawEVEXPackedMADD", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-evex-madd.ll", "raw-evex-madd.o", ir)
		})
	}
}
