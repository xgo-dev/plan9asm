package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeX86RawScaledRound(op Op, vectorBits, mask int, zeroing, evexB, memory bool) []byte {
	var opcode byte
	var w, scalar bool
	for encoding, form := range x86RawScaledRoundForms {
		if form.op == op {
			opcode = byte(encoding[0])
			w = encoding[1] != 0
			scalar = form.scalar
			break
		}
	}
	p1 := byte(0x7d)
	if scalar {
		p1 = 0x6d // EVEX.vvvv = X2 passthrough.
	}
	if w {
		p1 |= 0x80
	}
	p2 := byte(vectorBits<<5 | 0x08 | mask)
	if zeroing {
		p2 |= 0x80
	}
	if evexB {
		p2 |= 0x10
	}
	modRM := byte(0xd1) // first register 1, destination register 2.
	if scalar {
		modRM = 0xd9 // first register 1, destination register 3.
	}
	if memory {
		modRM = 0x50 // disp8(AX), destination register 2.
		if scalar {
			modRM = 0x58 // disp8(AX), destination register 3.
		}
	}
	code := []byte{0x62, 0xf3, p1, p2, opcode, modRM}
	if memory {
		code = append(code, 1)
	}
	return append(code, 9)
}

func TestDecodeX86RawScaledRoundSeBiShogunRegression(t *testing.T) {
	// Go disassembles these bytes as VRNDSCALEPS $9, 0(SI)(R8*4), Z0.
	code := []byte{0x62, 0xb3, 0x7d, 0x48, 0x08, 0x04, 0x86, 0x09, 0xc3}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "floorFloat32 AVX512 VRNDSCALEPS", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || decoded[0].Op != "VRNDSCALEPS" ||
		decoded[0].Args[0].Imm != 9 || decoded[0].Args[2].Reg != "Z0" {
		t.Fatalf("decoded %x as %#v", code, decoded)
	}
}

func TestDecodeX86RawScaledRoundCompleteGoForms(t *testing.T) {
	if len(x86RawScaledRoundForms) != 8 {
		t.Fatalf("modeled %d scaled-round rows, want eight", len(x86RawScaledRoundForms))
	}
	for _, form := range x86RawScaledRoundForms {
		maxLength := 2
		if form.scalar {
			maxLength = 0
		}
		for vectorBits := 0; vectorBits <= maxLength; vectorBits++ {
			for _, variant := range []struct {
				name    string
				mask    int
				zeroing bool
				evexB   bool
				memory  bool
				suffix  string
			}{
				{name: "register"},
				{name: "masked zero register", mask: 7, zeroing: true, suffix: ".Z"},
				{name: "memory", memory: true},
				{name: "broadcast memory", evexB: true, memory: true, suffix: ".BCST"},
				{name: "SAE register", evexB: true, suffix: ".SAE"},
			} {
				if form.scalar && variant.suffix == ".BCST" ||
					!form.scalar && variant.suffix == ".SAE" && vectorBits != 2 {
					continue
				}
				name := fmt.Sprintf("%s/length%d/%s", form.op, vectorBits, variant.name)
				t.Run(name, func(t *testing.T) {
					code := encodeX86RawScaledRound(form.op, vectorBits, variant.mask, variant.zeroing, variant.evexB, variant.memory)
					got, length, ok, err := decodedX86RawScaledRoundInstruction(code, 64)
					if err != nil || !ok || length != len(code) || got.Op != form.op+Op(variant.suffix) {
						t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
					}
					wantDestination := fmt.Sprintf("%s2", [...]string{"X", "Y", "Z"}[vectorBits])
					if form.scalar {
						wantDestination = "X3"
					}
					if got.Args[0].Imm != 9 || got.Args[len(got.Args)-1].String() != wantDestination {
						t.Fatalf("decode %x = %+v, want $9 ... %s", code, got, wantDestination)
					}
				})
			}
		}
	}
}

func TestDecodeX86RawScaledRoundRIPLiteral(t *testing.T) {
	for _, form := range x86RawScaledRoundForms {
		for _, broadcast := range []bool{false, true} {
			if broadcast && form.scalar {
				continue
			}
			vectorBits := 2
			if form.scalar {
				vectorBits = 0
			}
			code := encodeX86RawScaledRound(form.op, vectorBits, 1, false, broadcast, false)
			code = code[:6]
			code[5] = 0x15 // RIP-relative first source, destination 2.
			if form.scalar {
				code[5] = 0x1d // destination 3.
			}
			code = append(code, 1, 0, 0, 0, 9, 0xc3)
			literalWidth := 16 << vectorBits
			if form.scalar || broadcast {
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
				if len(got) != 2 || !got[0].x86RIPLiteral || len(got[0].x86RIPLiteralData) != literalWidth {
					t.Fatalf("decode %x = %+v", code, got)
				}
			})
		}
	}
}

func TestDecodeX86RawScaledRoundRejectsInvalidForms(t *testing.T) {
	base := encodeX86RawScaledRound("VRNDSCALEPS", 2, 0, false, false, false)
	for _, mutate := range []func([]byte){
		func(code []byte) { code[3] |= 0x80 },  // zeroing needs a mask
		func(code []byte) { code[3] |= 0x20 },  // reserved vector length
		func(code []byte) { code[2] &^= 0x08 }, // packed reserved vvvv
	} {
		code := append([]byte(nil), base...)
		mutate(code)
		if _, _, ok, err := decodedX86RawScaledRoundInstruction(code, 64); !ok || err == nil {
			t.Fatalf("invalid encoding %x returned ok=%v err=%v", code, ok, err)
		}
	}
	scalarBroadcast := encodeX86RawScaledRound("VRNDSCALESS", 0, 0, false, true, true)
	if _, _, ok, err := decodedX86RawScaledRoundInstruction(scalarBroadcast, 64); !ok || err == nil {
		t.Fatalf("accepted scalar broadcast %x: ok=%v err=%v", scalarBroadcast, ok, err)
	}
}

func TestTranslateX86RawScaledRoundLLVM22Objects(t *testing.T) {
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
			source.WriteString("TEXT rawScaledRound(SB),$0-0\n")
			for _, op := range []Op{"VRNDSCALEPS", "VRNDSCALEPD", "VREDUCEPS", "VREDUCEPD"} {
				code := encodeX86RawScaledRound(op, 0, 0, false, false, false)
				for _, value := range code {
					fmt.Fprintf(&source, "\tBYTE $0x%02x\n", value)
				}
			}
			if target.goarch == "amd64" {
				for _, op := range []Op{"VRNDSCALESS", "VRNDSCALESD", "VREDUCESS", "VREDUCESD"} {
					code := encodeX86RawScaledRound(op, 0, 0, false, false, false)
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
				Sigs: map[string]FuncSig{"rawScaledRound": {Name: "rawScaledRound", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-scaled-round.ll", "raw-scaled-round.o", ir)
		})
	}
}
