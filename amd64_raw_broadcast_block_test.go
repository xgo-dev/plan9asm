package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeX86RawBlockBroadcast(opcode, widthBit, vectorBits, mask int, zeroing, registerSource bool) []byte {
	p1 := byte(0x7d)
	if widthBit != 0 {
		p1 |= 0x80
	}
	p2 := byte(vectorBits<<5 | 0x08 | mask)
	if zeroing {
		p2 |= 0x80
	}
	modRM := byte(0x40) // disp8(AX), destination 0.
	if registerSource {
		modRM = 0xc1 // X1, destination 0.
	}
	code := []byte{0x62, 0xf2, p1, p2, byte(opcode), modRM}
	if !registerSource {
		code = append(code, 1)
	}
	return code
}

func TestDecodeX86RawBlockBroadcastSeBiShogunRegression(t *testing.T) {
	// Go disassembles the instruction as VBROADCASTI32X4 RIP+1, Z1.
	code := []byte{0x62, 0xf2, 0x7d, 0x48, 0x5a, 0x0d, 1, 0, 0, 0, 0xc3}
	for index := 0; index < 16; index++ {
		code = append(code, byte(index+1))
	}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "onesCountInt32 AVX512 block broadcast", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || decoded[0].Op != "VBROADCASTI32X4" ||
		decoded[0].Args[1].Reg != "Z1" || !decoded[0].x86RIPLiteral {
		t.Fatalf("decoded %x as %#v", code, decoded)
	}
}

func TestDecodeX86RawBlockBroadcastCompleteGoFamily(t *testing.T) {
	if len(x86RawBlockBroadcastForms) != 10 {
		t.Fatalf("modeled %d EVEX block-broadcast rows, want ten", len(x86RawBlockBroadcastForms))
	}
	for encoding, form := range x86RawBlockBroadcastForms {
		for vectorBits := form.minLength; vectorBits <= 2; vectorBits++ {
			for _, masking := range []struct {
				mask, zero int
			}{
				{}, {mask: 3}, {mask: 7, zero: 1},
			} {
				for _, registerSource := range []bool{false, true} {
					if registerSource && !form.allowX {
						continue
					}
					name := fmt.Sprintf("%s/length%d/mask%d/zero%d/reg%t", form.op, vectorBits, masking.mask, masking.zero, registerSource)
					t.Run(name, func(t *testing.T) {
						code := encodeX86RawBlockBroadcast(encoding[0], encoding[1], vectorBits, masking.mask, masking.zero != 0, registerSource)
						got, length, ok, err := decodedX86RawBlockBroadcastInstruction(code, 64)
						if err != nil || !ok || length != len(code) {
							t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
						}
						wantOp := form.op
						if masking.zero != 0 {
							wantOp += ".Z"
						}
						wantDestination := fmt.Sprintf("%s0", [...]string{"X", "Y", "Z"}[vectorBits])
						if got.Op != wantOp || got.Args[len(got.Args)-1].String() != wantDestination ||
							registerSource && got.Args[0].String() != "X1" ||
							len(got.Args) != 2+map[bool]int{true: 1}[masking.mask != 0] {
							t.Fatalf("decode %x = %+v, want %s ... %s", code, got, wantOp, wantDestination)
						}
					})
				}
			}
		}
	}
}

func TestDecodeX86RawBlockBroadcastRIPLiteralCompleteFamily(t *testing.T) {
	for encoding, form := range x86RawBlockBroadcastForms {
		for vectorBits := form.minLength; vectorBits <= 2; vectorBits++ {
			code := encodeX86RawBlockBroadcast(encoding[0], encoding[1], vectorBits, 1, false, false)
			code = code[:6]
			code[5] = 0x05 // RIP-relative source, destination 0.
			code = append(code, 1, 0, 0, 0, 0xc3)
			for index := 0; index < form.sourceBytes; index++ {
				code = append(code, byte(index+1))
			}
			name := fmt.Sprintf("%s/length%d", form.op, vectorBits)
			t.Run(name, func(t *testing.T) {
				got, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
				if err != nil {
					t.Fatal(err)
				}
				if len(got) != 2 || !got[0].x86RIPLiteral ||
					len(got[0].x86RIPLiteralData) != form.sourceBytes || got[0].Op != form.op {
					t.Fatalf("decode %x = %+v", code, got)
				}
			})
		}
	}
}

func TestDecodeX86RawBlockBroadcastRejectsInvalidForms(t *testing.T) {
	base := encodeX86RawBlockBroadcast(0x5a, 0, 2, 0, false, false)
	for _, mutate := range []func([]byte){
		func(code []byte) { code[3] |= 0x10 },  // no EVEX.b broadcast
		func(code []byte) { code[3] |= 0x80 },  // zeroing needs a mask
		func(code []byte) { code[3] |= 0x20 },  // vector length 3 reserved
		func(code []byte) { code[2] &^= 0x08 }, // reserved vvvv
	} {
		code := append([]byte(nil), base...)
		mutate(code)
		if _, _, ok, err := decodedX86RawBlockBroadcastInstruction(code, 64); !ok || err == nil {
			t.Fatalf("invalid encoding %x returned ok=%v err=%v", code, ok, err)
		}
	}
	registerSource := encodeX86RawBlockBroadcast(0x5a, 0, 2, 0, false, true)
	if _, _, ok, err := decodedX86RawBlockBroadcastInstruction(registerSource, 64); !ok || err == nil {
		t.Fatalf("accepted m128-only register source %x: ok=%v err=%v", registerSource, ok, err)
	}
}

func TestTranslateX86RawBlockBroadcastLLVM22Objects(t *testing.T) {
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
			source.WriteString("TEXT rawBlockBroadcast(SB),$0-0\n")
			for encoding, form := range x86RawBlockBroadcastForms {
				for vectorBits := form.minLength; vectorBits <= 2; vectorBits++ {
					for _, masking := range []struct {
						mask int
						zero bool
					}{
						{}, {mask: 3}, {mask: 7, zero: true},
					} {
						code := encodeX86RawBlockBroadcast(encoding[0], encoding[1], vectorBits, masking.mask, masking.zero, false)
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
				Sigs: map[string]FuncSig{"rawBlockBroadcast": {Name: "rawBlockBroadcast", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-block-broadcast.ll", "raw-block-broadcast.o", ir)
		})
	}
}
