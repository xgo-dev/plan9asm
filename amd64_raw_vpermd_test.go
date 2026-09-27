package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeX86RawEVEXVariableDwordPermute(opcode, vectorBits, mask int, zeroing, broadcast, memory bool) []byte {
	p2 := byte(vectorBits<<5 | 0x08 | mask)
	if zeroing {
		p2 |= 0x80
	}
	if broadcast {
		p2 |= 0x10
	}
	modRM := byte(0xd3) // data register 3, destination register 2.
	if memory {
		modRM = 0x50 // disp8(AX) data, destination register 2.
	}
	code := []byte{0x62, 0xf2, 0x75, p2, byte(opcode), modRM}
	if memory {
		code = append(code, 1)
	}
	return code
}

func TestDecodedX86VariableDwordPermuteInstructionCompleteVEXFamily(t *testing.T) {
	for _, test := range []struct {
		opcode byte
		op     Op
	}{
		{0x36, "VPERMD"},
		{0x16, "VPERMPS"},
	} {
		t.Run(string(test.op), func(t *testing.T) {
			code := []byte{0xc4, 0xe2, 0x25, test.opcode, 0xd6}
			instruction, length, ok, err := decodedX86VariableDwordPermuteInstruction(code, 64)
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				t.Fatal("encoding was not recognized")
			}
			if length != len(code) {
				t.Fatalf("length = %d, want %d", length, len(code))
			}
			want := string(test.op) + " Y6, Y11, Y2"
			if instruction.Op != test.op || instruction.Raw != want {
				t.Fatalf("instruction = %#v, want %q", instruction, want)
			}
		})
	}

	for _, test := range []struct {
		name string
		code []byte
		mode int
		want string
	}{
		{
			name: "extended_registers",
			code: []byte{0xc4, 0x42, 0x05, 0x36, 0xdb},
			mode: 64,
			want: "VPERMD Y11, Y15, Y11",
		},
		{
			name: "memory_sib_disp8",
			code: []byte{0xc4, 0x62, 0x15, 0x36, 0x5c, 0x88, 0x20},
			mode: 64,
			want: "VPERMD 32(AX)(CX*4), Y13, Y11",
		},
		{
			name: "memory_negative_disp8",
			code: []byte{0xc4, 0x62, 0x65, 0x16, 0x64, 0x35, 0xef},
			mode: 64,
			want: "VPERMPS -17(BP)(SI*1), Y3, Y12",
		},
		{
			name: "386_registers",
			code: []byte{0xc4, 0xe2, 0x65, 0x36, 0xe5},
			mode: 32,
			want: "VPERMD Y5, Y3, Y4",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			instruction, length, ok, err := decodedX86VariableDwordPermuteInstruction(test.code, test.mode)
			if err != nil {
				t.Fatal(err)
			}
			if !ok || length != len(test.code) || instruction.Raw != test.want {
				t.Fatalf("decode = (%#v, %d, %v), want %q", instruction, length, ok, test.want)
			}
		})
	}
}

func TestDecodeX86RawEVEXVPERMDSeBiShogunRegression(t *testing.T) {
	// Go disassembles these bytes as VPERMD Z2, Z0, Z3.
	code := []byte{0x62, 0xf2, 0x7d, 0x48, 0x36, 0xda, 0xc3}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "cumMinInt32 AVX512 VPERMD", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || decoded[0].Op != "VPERMD" ||
		decoded[0].Args[0].Reg != "Z2" || decoded[0].Args[1].Reg != "Z0" ||
		decoded[0].Args[2].Reg != "Z3" {
		t.Fatalf("decoded %x as %#v", code, decoded)
	}
}

func TestDecodeX86RawEVEXVariableDwordPermuteCompleteGoForms(t *testing.T) {
	for _, family := range []struct {
		opcode int
		op     Op
	}{
		{0x36, "VPERMD"},
		{0x16, "VPERMPS"},
	} {
		for vectorIndex, vector := range []string{"Y", "Z"} {
			vectorBits := vectorIndex + 1
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
				{name: "broadcast zeroing memory", mask: 1, zeroing: true, broadcast: true, memory: true},
			} {
				name := fmt.Sprintf("%s/%s/%s", family.op, vector, variant.name)
				t.Run(name, func(t *testing.T) {
					code := encodeX86RawEVEXVariableDwordPermute(family.opcode, vectorBits, variant.mask, variant.zeroing, variant.broadcast, variant.memory)
					got, length, ok, err := decodedX86EVEXVariableDwordPermuteInstruction(code, 64)
					if err != nil || !ok || length != len(code) {
						t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
					}
					wantOp := family.op
					if variant.broadcast {
						wantOp += ".BCST"
					}
					if variant.zeroing {
						wantOp += ".Z"
					}
					if got.Op != wantOp || got.Args[1].String() != vector+"1" ||
						got.Args[len(got.Args)-1].String() != vector+"2" ||
						!variant.memory && got.Args[0].String() != vector+"3" ||
						len(got.Args) != 3+map[bool]int{true: 1}[variant.mask != 0] {
						t.Fatalf("decode %x = %+v, want %s", code, got, wantOp)
					}
				})
			}
		}
	}
}

func TestDecodeX86RawEVEXVariableDwordPermuteRIPLiteral(t *testing.T) {
	for _, family := range []struct {
		opcode int
		op     Op
	}{
		{0x36, "VPERMD"},
		{0x16, "VPERMPS"},
	} {
		for vectorBits := 1; vectorBits <= 2; vectorBits++ {
			for _, broadcast := range []bool{false, true} {
				code := encodeX86RawEVEXVariableDwordPermute(family.opcode, vectorBits, 1, false, broadcast, false)
				code[5] = 0x15 // RIP-relative first source.
				code = append(code, 1, 0, 0, 0, 0xc3)
				literalWidth := 16 << vectorBits
				if broadcast {
					literalWidth = 4
				}
				for index := 0; index < literalWidth; index++ {
					code = append(code, byte(index+1))
				}
				name := fmt.Sprintf("%s/width%d/broadcast%t", family.op, vectorBits, broadcast)
				t.Run(name, func(t *testing.T) {
					got, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
					if err != nil {
						t.Fatal(err)
					}
					if len(got) != 2 || !got[0].x86RIPLiteral ||
						len(got[0].x86RIPLiteralData) != literalWidth {
						t.Fatalf("decode %x = %+v", code, got)
					}
				})
			}
		}
	}
}

func TestDecodeX86RawEVEXVariableDwordPermuteRejectsInvalidForms(t *testing.T) {
	base := encodeX86RawEVEXVariableDwordPermute(0x36, 2, 0, false, false, false)
	for _, mutate := range []func([]byte){
		func(code []byte) { code[2] |= 0x80 },  // Go's EVEX.W is zero
		func(code []byte) { code[3] &^= 0x60 }, // no X-width EVEX form
		func(code []byte) { code[3] |= 0x80 },  // zeroing without mask
		func(code []byte) { code[3] |= 0x10 },  // broadcast requires memory
	} {
		code := append([]byte(nil), base...)
		mutate(code)
		if _, _, ok, err := decodedX86EVEXVariableDwordPermuteInstruction(code, 64); !ok || err == nil {
			t.Fatalf("invalid encoding %x returned ok=%v err=%v", code, ok, err)
		}
	}
	if _, _, ok, err := decodedX86EVEXVariableDwordPermuteInstruction(
		encodeX86RawEVEXVariableDwordPermute(0x16, 2, 1, false, false, false), 32,
	); !ok || err == nil {
		t.Fatalf("accepted 386 masked form: ok=%v err=%v", ok, err)
	}
}

func TestTranslateX86RawEVEXVariableDwordPermuteLLVM22Objects(t *testing.T) {
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
			source.WriteString("TEXT rawVariableDwordPermute(SB),$0-0\n")
			for _, opcode := range []int{0x36, 0x16} {
				for _, vectorBits := range []int{1, 2} {
					mask := 1
					if target.goarch == "386" {
						mask = 0
					}
					for _, memory := range []bool{false, true} {
						code := encodeX86RawEVEXVariableDwordPermute(opcode, vectorBits, mask, false, false, memory)
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
				Sigs: map[string]FuncSig{"rawVariableDwordPermute": {Name: "rawVariableDwordPermute", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-vpermd.ll", "raw-vpermd.o", ir)
		})
	}
}

func TestDecodedX86VariableDwordPermuteInstructionRejectsInvalidVEXForms(t *testing.T) {
	for _, test := range []struct {
		name string
		code []byte
		mode int
	}{
		{name: "truncated_modrm", code: []byte{0xc4, 0xe2, 0x25, 0x36}, mode: 64},
		{name: "vex_l_zero", code: []byte{0xc4, 0xe2, 0x21, 0x36, 0xd6}, mode: 64},
		{name: "vex_pp_zero", code: []byte{0xc4, 0xe2, 0x24, 0x36, 0xd6}, mode: 64},
		{name: "vex_w_one", code: []byte{0xc4, 0xe2, 0xa5, 0x36, 0xd6}, mode: 64},
		{name: "address_override", code: []byte{0x67, 0xc4, 0xe2, 0x25, 0x36, 0xd6}, mode: 64},
		{name: "extended_register_in_386", code: []byte{0xc4, 0x42, 0x05, 0x36, 0xdb}, mode: 32},
		{name: "rip_relative", code: []byte{0xc4, 0xe2, 0x25, 0x36, 0x05, 0, 0, 0, 0}, mode: 64},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, ok, err := decodedX86VariableDwordPermuteInstruction(test.code, test.mode)
			if !ok {
				t.Fatal("VPERMD/VPERMPS encoding was not recognized")
			}
			if err == nil {
				t.Fatal("invalid encoding was accepted")
			}
		})
	}
}

func TestDecodeX86RawDirectiveGroupVPERMDReportedSequence(t *testing.T) {
	code := []byte{
		0xc4, 0xe2, 0x25, 0x36, 0xd6,
		0xc4, 0xe2, 0x7d, 0x36, 0xd6,
		0xc4, 0xe2, 0x35, 0x36, 0xd6,
	}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "go-pherence VEX VPERMD sequence", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 3 {
		t.Fatalf("decoded %d instructions, want 3: %#v", len(decoded), decoded)
	}
	for _, instruction := range decoded {
		if instruction.Op != "VPERMD" {
			t.Fatalf("decoded op = %s, want VPERMD", instruction.Op)
		}
	}
}
