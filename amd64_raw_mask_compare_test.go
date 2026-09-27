package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeX86RawMaskCompare(opcode, widthBit, vectorBits, writeMask int, broadcast, memory bool) []byte {
	p1 := byte(0x5d) // EVEX.vvvv = vector register 4, pp = 66.
	if widthBit != 0 {
		p1 |= 0x80
	}
	p2 := byte(vectorBits<<5 | 0x08 | writeMask)
	if broadcast {
		p2 |= 0x10
	}
	modRM := byte(0xd3) // first register 3, K destination 2.
	if memory {
		modRM = 0x50 // disp8(AX), K destination 2.
	}
	code := []byte{0x62, 0xf3, p1, p2, byte(opcode), modRM}
	if memory {
		code = append(code, 1)
	}
	return append(code, 6)
}

func TestDecodeX86RawMaskCompareSeBiShogunRegression(t *testing.T) {
	// Go disassembles these bytes as VPCMPUB $6, 0(SI)(R8*1), Z0, K0.
	code := []byte{0x62, 0xb3, 0x7d, 0x48, 0x3e, 0x04, 0x06, 0x06, 0xc3}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "maskBitsLess AVX512 VPCMPUB", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || decoded[0].Op != "VPCMPUB" ||
		decoded[0].Args[0].Imm != 6 || decoded[0].Args[2].Reg != "Z0" ||
		decoded[0].Args[3].Reg != "K0" {
		t.Fatalf("decoded %x as %#v", code, decoded)
	}
}

func TestDecodeX86RawMaskCompareCompleteGoForms(t *testing.T) {
	if len(x86RawMaskCompareForms) != 8 {
		t.Fatalf("modeled %d EVEX mask-compare rows, want eight", len(x86RawMaskCompareForms))
	}
	for encoding, form := range x86RawMaskCompareForms {
		for vectorBits := 0; vectorBits < 3; vectorBits++ {
			vector := [...]string{"X", "Y", "Z"}[vectorBits]
			for _, variant := range []struct {
				name      string
				writeMask int
				broadcast bool
				memory    bool
			}{
				{name: "register"},
				{name: "masked register", writeMask: 3},
				{name: "memory", memory: true},
				{name: "masked memory", writeMask: 7, memory: true},
				{name: "broadcast memory", broadcast: true, memory: true},
			} {
				if variant.broadcast && form.laneBytes < 4 {
					continue
				}
				name := fmt.Sprintf("%s/%s/%s", form.op, vector, variant.name)
				t.Run(name, func(t *testing.T) {
					code := encodeX86RawMaskCompare(encoding[0], encoding[1], vectorBits, variant.writeMask, variant.broadcast, variant.memory)
					got, length, ok, err := decodedX86RawMaskCompareInstruction(code, 64)
					if err != nil || !ok || length != len(code) {
						t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
					}
					wantOp := form.op
					if variant.broadcast {
						wantOp += ".BCST"
					}
					if got.Op != wantOp || got.Args[0].Imm != 6 || got.Args[2].String() != vector+"4" ||
						got.Args[len(got.Args)-1].String() != "K2" ||
						!variant.memory && got.Args[1].String() != vector+"3" ||
						len(got.Args) != 4+map[bool]int{true: 1}[variant.writeMask != 0] {
						t.Fatalf("decode %x = %+v, want %s", code, got, wantOp)
					}
				})
			}
		}
	}
}

func TestDecodeX86RawMaskCompareRIPLiteral(t *testing.T) {
	for encoding, form := range x86RawMaskCompareForms {
		for _, broadcast := range []bool{false, true} {
			if broadcast && form.laneBytes < 4 {
				continue
			}
			code := encodeX86RawMaskCompare(encoding[0], encoding[1], 2, 1, broadcast, false)
			code = code[:6]
			code[5] = 0x15 // RIP-relative first source, K destination 2.
			code = append(code, 1, 0, 0, 0, 6, 0xc3)
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

func TestDecodeX86RawMaskCompareRejectsInvalidForms(t *testing.T) {
	base := encodeX86RawMaskCompare(0x3e, 0, 2, 0, false, false)
	for _, mutate := range []func([]byte){
		func(code []byte) { code[3] |= 0x80 },  // no EVEX zeroing
		func(code []byte) { code[3] |= 0x20 },  // reserved vector length
		func(code []byte) { code[3] |= 0x10 },  // byte broadcast unavailable
		func(code []byte) { code[1] &^= 0x80 }, // K destination extension
	} {
		code := append([]byte(nil), base...)
		mutate(code)
		if _, _, ok, err := decodedX86RawMaskCompareInstruction(code, 64); !ok || err == nil {
			t.Fatalf("invalid encoding %x returned ok=%v err=%v", code, ok, err)
		}
	}
	if _, _, ok, err := decodedX86RawMaskCompareInstruction(base, 32); !ok || err == nil {
		t.Fatalf("accepted 386 mask compare: ok=%v err=%v", ok, err)
	}
}

func TestTranslateX86RawMaskCompareLLVM22Objects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"x86_64-apple-darwin",
		"x86_64-unknown-linux-gnu",
		"x86_64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT rawMaskCompare(SB),$0-0\n")
			for encoding, form := range x86RawMaskCompareForms {
				code := encodeX86RawMaskCompare(encoding[0], encoding[1], 0, 0, false, false)
				for _, value := range code {
					fmt.Fprintf(&source, "\tBYTE $0x%02x\n", value)
				}
				if form.laneBytes >= 4 {
					code = encodeX86RawMaskCompare(encoding[0], encoding[1], 0, 3, true, true)
					for _, value := range code {
						fmt.Fprintf(&source, "\tBYTE $0x%02x\n", value)
					}
				}
			}
			source.WriteString("\tRET\n")
			requireX86GoAssemblerResult(t, "amd64", source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: "amd64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"rawMaskCompare": {Name: "rawMaskCompare", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "raw-mask-compare.ll", "raw-mask-compare.o", ir)
		})
	}
}
