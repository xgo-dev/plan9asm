package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeX86RawVariableRotate(op Op, width, mask, destination, first, second int, zeroing, broadcast, memory bool) []byte {
	opcode := byte(0x14)
	if strings.HasPrefix(string(op), "VPROL") {
		opcode = 0x15
	}
	p0 := byte((1-(destination>>3)&1)<<7 | (1-(first>>4)&1)<<6 |
		(1-(first>>3)&1)<<5 | (1-(destination>>4)&1)<<4 | 2)
	p1 := byte(((^second)&15)<<3 | 0x05)
	if strings.HasSuffix(string(op), "Q") {
		p1 |= 0x80
	}
	p2 := byte(width<<5 | (1-((second>>4)&1))<<3 | mask)
	if zeroing {
		p2 |= 0x80
	}
	if broadcast {
		p2 |= 0x10
	}
	modRM := byte(0xc0 | (destination&7)<<3 | first&7)
	if memory {
		modRM = byte(0x40 | (destination&7)<<3)
		p0 = byte((1-(destination>>3)&1)<<7 | 0x60 | (1-(destination>>4)&1)<<4 | 2)
	}
	code := []byte{0x62, p0, p1, p2, opcode, modRM}
	if memory {
		code = append(code, 1)
	}
	return code
}

func TestDecodeX86RawVariableRotateSeBiShogunRegression(t *testing.T) {
	// Go's assembler disassembles these bytes as VPROLVD Z0, Z1, Z1.
	code := []byte{0x62, 0xf2, 0x75, 0x48, 0x15, 0xc8, 0xc3}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "rotlInt32 AVX512 VPROLVD", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || decoded[0].Op != "VPROLVD" ||
		decoded[0].Args[0].Reg != "Z0" || decoded[0].Args[1].Reg != "Z1" ||
		decoded[0].Args[2].Reg != "Z1" {
		t.Fatalf("decoded %x as %#v", code, decoded)
	}
}

func TestDecodeX86RawVariableRotateCompleteGoForms(t *testing.T) {
	for _, op := range []Op{"VPROLVD", "VPROLVQ", "VPRORVD", "VPRORVQ"} {
		for width := 0; width < 3; width++ {
			vector := [...]string{"X", "Y", "Z"}[width]
			for _, form := range []struct {
				name        string
				mask        int
				zeroing     bool
				broadcast   bool
				memory      bool
				destination int
				first       int
				second      int
			}{
				{name: "register", destination: 2, first: 3, second: 4},
				{name: "high registers", destination: 18, first: 19, second: 20},
				{name: "masked zeroing", mask: 7, zeroing: true, destination: 2, first: 3, second: 4},
				{name: "memory", memory: true, destination: 2, second: 4},
				{name: "broadcast memory", broadcast: true, memory: true, destination: 2, second: 4},
				{name: "broadcast zeroing memory", broadcast: true, memory: true, mask: 5, zeroing: true, destination: 2, second: 4},
			} {
				name := fmt.Sprintf("%s/%s/%s", op, vector, form.name)
				t.Run(name, func(t *testing.T) {
					code := encodeX86RawVariableRotate(
						op, width, form.mask, form.destination, form.first, form.second,
						form.zeroing, form.broadcast, form.memory,
					)
					got, length, ok, err := decodedX86RawVariableRotateInstruction(code, 64)
					if err != nil || !ok || length != len(code) {
						t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
					}
					wantOp := op
					if form.broadcast {
						wantOp += ".BCST"
					}
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

func TestDecodeX86RawVariableRotateRIPLiteral(t *testing.T) {
	for _, op := range []Op{"VPROLVD", "VPROLVQ", "VPRORVD", "VPRORVQ"} {
		for width := 0; width < 3; width++ {
			for _, broadcast := range []bool{false, true} {
				code := encodeX86RawVariableRotate(op, width, 1, 2, 0, 4, false, broadcast, false)
				code[5] = 0x15 // RIP-relative first source, destination 2.
				code = append(code, 1, 0, 0, 0, 0xc3)
				literalWidth := 16 << width
				if broadcast {
					literalWidth = 4
					if strings.HasSuffix(string(op), "Q") {
						literalWidth = 8
					}
				}
				for index := 0; index < literalWidth; index++ {
					code = append(code, byte(index+1))
				}
				name := fmt.Sprintf("%s/width%d/broadcast%t", op, width, broadcast)
				t.Run(name, func(t *testing.T) {
					got, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
					if err != nil {
						t.Fatal(err)
					}
					if len(got) != 2 || !got[0].x86RIPLiteral || len(got[0].x86RIPLiteralData) != literalWidth {
						t.Fatalf("decode %x = %+v", code, got)
					}
				})
			}
		}
	}
}

func TestDecodeX86RawVariableRotateRejectsInvalidForms(t *testing.T) {
	base := encodeX86RawVariableRotate("VPROLVD", 2, 0, 2, 3, 4, false, false, false)
	for _, mutate := range []func([]byte){
		func(code []byte) { code[3] |= 0x10 }, // broadcast requires memory
		func(code []byte) { code[3] |= 0x80 }, // zeroing requires a mask
		func(code []byte) { code[3] |= 0x20 }, // reserved vector length
	} {
		code := append([]byte(nil), base...)
		mutate(code)
		if _, _, ok, err := decodedX86RawVariableRotateInstruction(code, 64); !ok || err == nil {
			t.Fatalf("invalid encoding %x returned ok=%v err=%v", code, ok, err)
		}
	}
}

func TestTranslateX86RawVariableRotateLLVM22Objects(t *testing.T) {
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
			source.WriteString("TEXT rawVariableRotate(SB),$0-0\n")
			for _, op := range []Op{"VPROLVD", "VPROLVQ", "VPRORVD", "VPRORVQ"} {
				for width := 0; width < 3; width++ {
					for _, form := range []struct {
						memory, broadcast bool
					}{
						{}, {memory: true}, {memory: true, broadcast: true},
					} {
						code := encodeX86RawVariableRotate(op, width, 0, 2, 3, 4, false, form.broadcast, form.memory)
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
				Sigs: map[string]FuncSig{"rawVariableRotate": {Name: "rawVariableRotate", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-variable-rotate.ll", "raw-variable-rotate.o", ir)
		})
	}
}
