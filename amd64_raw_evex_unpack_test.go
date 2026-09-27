package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeX86RawEVEXUnpack(opcode, width, mask int, zeroing, broadcast, memory bool) []byte {
	form := x86RawEVEXUnpackForms[opcode]
	p1 := byte(0x5d) // EVEX.vvvv = source register 4, pp = 66.
	if form.w {
		p1 |= 0x80
	}
	p2 := byte(width<<5 | 0x08 | mask)
	if zeroing {
		p2 |= 0x80
	}
	if broadcast {
		p2 |= 0x10
	}
	modRM := byte(0xd3) // first register 3, destination register 2.
	if memory {
		modRM = 0x50 // disp8(AX), destination register 2.
	}
	code := []byte{0x62, 0xf1, p1, p2, byte(opcode), modRM}
	if memory {
		code = append(code, 1)
	}
	return code
}

func TestDecodeX86RawEVEXUnpackSeBiShogunRegression(t *testing.T) {
	// Go's assembler disassembles these bytes as VPUNPCKHDQ Z2, Z3, Z7.
	code := []byte{0x62, 0xf1, 0x65, 0x48, 0x6a, 0xfa, 0xc3}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "onesCountInt32 AVX512 VPUNPCKHDQ", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || decoded[0].Op != "VPUNPCKHDQ" ||
		decoded[0].Args[0].Reg != "Z2" || decoded[0].Args[1].Reg != "Z3" ||
		decoded[0].Args[2].Reg != "Z7" {
		t.Fatalf("decoded %x as %#v", code, decoded)
	}
}

func TestDecodeX86RawEVEXUnpackCompleteGoForms(t *testing.T) {
	if len(x86RawEVEXUnpackForms) != 8 {
		t.Fatalf("modeled %d EVEX unpack rows, want eight", len(x86RawEVEXUnpackForms))
	}
	for opcode, form := range x86RawEVEXUnpackForms {
		for width := 0; width < 3; width++ {
			vector := [...]string{"X", "Y", "Z"}[width]
			for _, variant := range []struct {
				name      string
				mask      int
				zeroing   bool
				broadcast bool
				memory    bool
			}{
				{name: "register"},
				{name: "masked register", mask: 3},
				{name: "memory", memory: true},
				{name: "zeroing memory", mask: 7, zeroing: true, memory: true},
				{name: "broadcast memory", broadcast: true, memory: true},
				{name: "broadcast zero memory", broadcast: true, mask: 7, zeroing: true, memory: true},
			} {
				if variant.broadcast && form.broadcastBytes == 0 {
					continue
				}
				name := fmt.Sprintf("%s/%s/%s", form.op, vector, variant.name)
				t.Run(name, func(t *testing.T) {
					code := encodeX86RawEVEXUnpack(opcode, width, variant.mask, variant.zeroing, variant.broadcast, variant.memory)
					got, length, ok, err := decodedX86EVEXPackedUnpackInstruction(code, 64)
					if err != nil || !ok || length != len(code) {
						t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
					}
					wantOp := form.op
					if variant.broadcast {
						wantOp += ".BCST"
					}
					if variant.zeroing {
						wantOp += ".Z"
					}
					if got.Op != wantOp || got.Args[1].String() != vector+"4" ||
						got.Args[len(got.Args)-1].String() != vector+"2" ||
						!variant.memory && got.Args[0].String() != vector+"3" {
						t.Fatalf("decode %x = %+v, want %s", code, got, wantOp)
					}
				})
			}
		}
	}
}

func TestDecodeX86RawEVEXUnpackRIPLiteral(t *testing.T) {
	for opcode, form := range x86RawEVEXUnpackForms {
		for width := 0; width < 3; width++ {
			for _, broadcast := range []bool{false, true} {
				if broadcast && form.broadcastBytes == 0 {
					continue
				}
				code := encodeX86RawEVEXUnpack(opcode, width, 1, false, broadcast, false)
				code[5] = 0x15 // RIP-relative first source, destination 2.
				code = append(code, 1, 0, 0, 0, 0xc3)
				literalWidth := 16 << width
				if broadcast {
					literalWidth = form.broadcastBytes
				}
				for index := 0; index < literalWidth; index++ {
					code = append(code, byte(index+1))
				}
				name := fmt.Sprintf("%s/width%d/broadcast%t", form.op, width, broadcast)
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
}

func TestDecodeX86RawEVEXUnpackRejectsInvalidForms(t *testing.T) {
	base := encodeX86RawEVEXUnpack(0x6a, 2, 0, false, false, false)
	for _, mutate := range []func([]byte){
		func(code []byte) { code[2] |= 0x80 }, // HDQ requires EVEX.W0
		func(code []byte) { code[3] |= 0x80 }, // zeroing needs a mask
		func(code []byte) { code[3] |= 0x10 }, // broadcast requires memory
		func(code []byte) { code[3] |= 0x20 }, // reserved vector length
	} {
		code := append([]byte(nil), base...)
		mutate(code)
		if _, _, ok, err := decodedX86EVEXPackedUnpackInstruction(code, 64); !ok || err == nil {
			t.Fatalf("invalid encoding %x returned ok=%v err=%v", code, ok, err)
		}
	}
	byteBroadcast := encodeX86RawEVEXUnpack(0x60, 2, 0, false, true, true)
	if _, _, ok, err := decodedX86EVEXPackedUnpackInstruction(byteBroadcast, 64); !ok || err == nil {
		t.Fatalf("accepted VPUNPCKLBW broadcast %x: ok=%v err=%v", byteBroadcast, ok, err)
	}
}

func TestTranslateX86RawEVEXUnpackLLVM22Objects(t *testing.T) {
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
			source.WriteString("TEXT rawEVEXUnpack(SB),$0-0\n")
			for opcode, form := range x86RawEVEXUnpackForms {
				for width := 0; width < 3; width++ {
					for _, variant := range []struct {
						memory, broadcast bool
					}{
						{}, {memory: true}, {memory: true, broadcast: true},
					} {
						if variant.broadcast && form.broadcastBytes == 0 {
							continue
						}
						code := encodeX86RawEVEXUnpack(opcode, width, 0, false, variant.broadcast, variant.memory)
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
				Sigs: map[string]FuncSig{"rawEVEXUnpack": {Name: "rawEVEXUnpack", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-evex-unpack.ll", "raw-evex-unpack.o", ir)
		})
	}
}
