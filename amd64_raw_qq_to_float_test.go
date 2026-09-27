package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func x86RawQQToPSEncoding(unsigned bool, vectorBits, mask int, zeroing, broadcast, memory bool) []byte {
	p1, opcode := byte(0xfc), byte(0x5b)
	if unsigned {
		p1, opcode = 0xff, 0x7a
	}
	p2 := byte(vectorBits<<5 | 0x08 | mask)
	if zeroing {
		p2 |= 0x80
	}
	if broadcast {
		p2 |= 0x10
	}
	modRM := byte(0xc1) // source register 1, destination register 0.
	if memory {
		modRM = 0x40 // disp8(AX), destination register 0.
	}
	code := []byte{0x62, 0xf1, p1, p2, opcode, modRM}
	if memory {
		code = append(code, 1)
	}
	return code
}

func x86RawQQToPDEncoding(unsigned bool, vectorBits, mask int, zeroing, broadcast, memory bool) []byte {
	code := x86RawQQToPSEncoding(unsigned, vectorBits, mask, zeroing, broadcast, memory)
	code[2] = 0xfe // EVEX.W1, F3 mandatory prefix.
	if !unsigned {
		code[4] = 0xe6
	}
	return code
}

func TestDecodeX86RawQQToPSRampAVX512Regression(t *testing.T) {
	// Go's assembler decodes these bytes as VCVTQQ2PS Z5, Y16.
	code := []byte{0x62, 0xe1, 0xfc, 0x48, 0x5b, 0xc5, 0xc3}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "ramp AVX512 QQ to PS", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || decoded[0].Op != "VCVTQQ2PS" ||
		decoded[0].Args[0].Reg != "Z5" || decoded[0].Args[1].Reg != "Y16" {
		t.Fatalf("decoded %x as %#v", code, decoded)
	}
}

func TestDecodeX86RawQQToPDRampAVX512Regression(t *testing.T) {
	// Go's assembler decodes these bytes as VCVTQQ2PD Z4, Z12.
	code := []byte{0x62, 0x71, 0xfe, 0x48, 0xe6, 0xe4, 0xc3}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "ramp AVX512 QQ to PD", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || decoded[0].Op != "VCVTQQ2PD" ||
		decoded[0].Args[0].Reg != "Z4" || decoded[0].Args[1].Reg != "Z12" {
		t.Fatalf("decoded %x as %#v", code, decoded)
	}
}

func TestDecodeX86RawQQToPSCompleteGoForms(t *testing.T) {
	for _, unsigned := range []bool{false, true} {
		base := "VCVTQQ2PS"
		if unsigned {
			base = "VCVTUQQ2PS"
		}
		for width := 0; width < 3; width++ {
			baseOp := base + [...]string{"X", "Y", ""}[width]
			source := [...]string{"X1", "Y1", "Z1"}[width]
			destination := [...]string{"X0", "X0", "Y0"}[width]
			for _, form := range []struct {
				name      string
				mask      int
				zeroing   bool
				broadcast bool
				memory    bool
				op        string
			}{
				{name: "register", op: baseOp},
				{name: "masked register", mask: 3, op: baseOp},
				{name: "zero register", mask: 7, zeroing: true, op: baseOp + ".Z"},
				{name: "memory", memory: true, op: baseOp},
				{name: "broadcast memory", memory: true, broadcast: true, op: baseOp + ".BCST"},
				{name: "broadcast zero memory", mask: 7, zeroing: true, memory: true, broadcast: true, op: baseOp + ".BCST.Z"},
			} {
				name := fmt.Sprintf("%s/width%d/%s", base, width, form.name)
				t.Run(name, func(t *testing.T) {
					code := x86RawQQToPSEncoding(unsigned, width, form.mask, form.zeroing, form.broadcast, form.memory)
					got, length, ok, err := decodedX86RawQQToFloatInstruction(code, 64)
					if err != nil || !ok || length != len(code) {
						t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
					}
					if got.Op != Op(form.op) || got.Args[len(got.Args)-1].String() != destination {
						t.Fatalf("decode %x = %+v, want %s ... %s", code, got, form.op, destination)
					}
					if !form.memory && got.Args[0].String() != source {
						t.Fatalf("decode %x source = %s, want %s", code, got.Args[0], source)
					}
					if len(got.Args) != 2+map[bool]int{true: 1}[form.mask != 0] {
						t.Fatalf("decode %x operands = %+v", code, got.Args)
					}
				})
			}
		}
		for rounding := 0; rounding < 4; rounding++ {
			code := x86RawQQToPSEncoding(unsigned, rounding, 4, true, true, false)
			got, length, ok, err := decodedX86RawQQToFloatInstruction(code, 64)
			want := base + [...]string{".RN_SAE.Z", ".RD_SAE.Z", ".RU_SAE.Z", ".RZ_SAE.Z"}[rounding]
			if err != nil || !ok || length != len(code) || string(got.Op) != want ||
				got.Args[0].String() != "Z1" || got.Args[2].String() != "Y0" {
				t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v; want %s Z1, K4, Y0", code, got, length, ok, err, want)
			}
		}
	}
}

func TestDecodeX86RawQQToPDCompleteGoForms(t *testing.T) {
	for _, unsigned := range []bool{false, true} {
		base := "VCVTQQ2PD"
		if unsigned {
			base = "VCVTUQQ2PD"
		}
		for width := 0; width < 3; width++ {
			vector := [...]string{"X", "Y", "Z"}[width]
			for _, form := range []struct {
				name      string
				mask      int
				zeroing   bool
				broadcast bool
				memory    bool
				suffix    string
			}{
				{name: "register"},
				{name: "masked zero register", mask: 5, zeroing: true, suffix: ".Z"},
				{name: "memory", memory: true},
				{name: "broadcast memory", memory: true, broadcast: true, suffix: ".BCST"},
				{name: "broadcast zero memory", memory: true, broadcast: true, mask: 7, zeroing: true, suffix: ".BCST.Z"},
			} {
				name := fmt.Sprintf("%s/width%d/%s", base, width, form.name)
				t.Run(name, func(t *testing.T) {
					code := x86RawQQToPDEncoding(unsigned, width, form.mask, form.zeroing, form.broadcast, form.memory)
					got, length, ok, err := decodedX86RawQQToFloatInstruction(code, 64)
					if err != nil || !ok || length != len(code) || got.Op != Op(base+form.suffix) ||
						got.Args[len(got.Args)-1].String() != vector+"0" {
						t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
					}
					if !form.memory && got.Args[0].String() != vector+"1" {
						t.Fatalf("decode %x source = %s, want %s1", code, got.Args[0], vector)
					}
				})
			}
		}
		for rounding := 0; rounding < 4; rounding++ {
			code := x86RawQQToPDEncoding(unsigned, rounding, 4, true, true, false)
			got, length, ok, err := decodedX86RawQQToFloatInstruction(code, 64)
			want := base + [...]string{".RN_SAE.Z", ".RD_SAE.Z", ".RU_SAE.Z", ".RZ_SAE.Z"}[rounding]
			if err != nil || !ok || length != len(code) || string(got.Op) != want ||
				got.Args[0].String() != "Z1" || got.Args[2].String() != "Z0" {
				t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v; want %s Z1, K4, Z0", code, got, length, ok, err, want)
			}
		}
	}
}

func TestDecodeX86RawQQToFloatRIPLiteral(t *testing.T) {
	for _, kind := range []struct {
		name   string
		encode func(bool, int, int, bool, bool, bool) []byte
	}{
		{name: "PS", encode: x86RawQQToPSEncoding},
		{name: "PD", encode: x86RawQQToPDEncoding},
	} {
		for _, unsigned := range []bool{false, true} {
			for width := 0; width < 3; width++ {
				for _, broadcast := range []bool{false, true} {
					code := kind.encode(unsigned, width, 1, false, broadcast, false)
					code[5] = 0x05 // RIP-relative source, destination 0.
					code = append(code, 1, 0, 0, 0, 0xc3)
					literalWidth := 16 << width
					if broadcast {
						literalWidth = 8
					}
					for index := 0; index < literalWidth; index++ {
						code = append(code, byte(index+1))
					}
					name := fmt.Sprintf("%s/unsigned%t/width%d/broadcast%t", kind.name, unsigned, width, broadcast)
					t.Run(name, func(t *testing.T) {
						decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
						if err != nil {
							t.Fatal(err)
						}
						if len(decoded) != 2 || !decoded[0].x86RIPLiteral ||
							len(decoded[0].x86RIPLiteralData) != literalWidth ||
							broadcast != strings.Contains(string(decoded[0].Op), ".BCST") {
							t.Fatalf("decoded %x as %+v", code, decoded)
						}
					})
				}
			}
		}
	}
}

func TestTranslateX86RawQQToFloatLLVM22Objects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{"darwin-amd64", "amd64", "x86_64-apple-darwin"},
		{"linux-amd64", "amd64", "x86_64-unknown-linux-gnu"},
		{"windows-amd64", "amd64", "x86_64-pc-windows-msvc"},
		{"linux-386", "386", "i386-unknown-linux-gnu"},
		{"windows-386", "386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT rawQQToFloat(SB),$0-0\n")
			appendBytes := func(code []byte) {
				for _, value := range code {
					fmt.Fprintf(&source, "\tBYTE $0x%02x\n", value)
				}
			}
			for _, encode := range []func(bool, int, int, bool, bool, bool) []byte{
				x86RawQQToPSEncoding,
				x86RawQQToPDEncoding,
			} {
				for _, unsigned := range []bool{false, true} {
					for width := 0; width < 3; width++ {
						appendBytes(encode(unsigned, width, 0, false, false, false))
						appendBytes(encode(unsigned, width, 0, false, false, true))
						appendBytes(encode(unsigned, width, 0, false, true, true))
						if target.goarch == "amd64" {
							appendBytes(encode(unsigned, width, 7, true, false, false))
							appendBytes(encode(unsigned, width, 7, true, true, true))
						}
					}
					if target.goarch == "amd64" {
						for rounding := 0; rounding < 4; rounding++ {
							appendBytes(encode(unsigned, rounding, 4, true, true, false))
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
				Sigs: map[string]FuncSig{"rawQQToFloat": {Name: "rawQQToFloat", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-qq-to-float.ll", "raw-qq-to-float.o", ir)
		})
	}
}

func TestDecodeX86RawQQToPSRejectsInvalidForms(t *testing.T) {
	zeroWithoutMask := x86RawQQToPSEncoding(false, 0, 0, true, false, false)
	reservedLength := x86RawQQToPSEncoding(false, 3, 0, false, false, false)
	reservedVVVV := x86RawQQToPSEncoding(false, 0, 0, false, false, false)
	reservedVVVV[2] &^= 0x08
	for _, code := range [][]byte{zeroWithoutMask, reservedLength, reservedVVVV} {
		if _, _, ok, err := decodedX86RawQQToFloatInstruction(code, 64); !ok || err == nil {
			t.Fatalf("invalid %x returned ok=%v, err=%v", code, ok, err)
		}
	}
}
