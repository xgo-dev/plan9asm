package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func x86RawCLMULCode(encoding string, width int, source, second, destination int, immediate byte) []byte {
	modRM := byte(0xc0 | (destination&7)<<3 | source&7)
	switch encoding {
	case "legacy":
		code := []byte{0x66}
		rex := byte(0x40 | (destination>>3&1)<<2 | source>>3&1)
		if rex != 0x40 {
			code = append(code, rex)
		}
		return append(code, 0x0f, 0x3a, 0x44, modRM, immediate)
	case "vex":
		p0 := byte((1-destination/8)<<7 | 1<<6 | (1-source/8)<<5 | 3)
		p1 := byte(((^second)&15)<<3 | ((width-16)/16)<<2 | 1)
		return []byte{0xc4, p0, p1, 0x44, modRM, immediate}
	default:
		p0 := byte((1-destination/8&1)<<7 | (1-source/16&1)<<6 |
			(1-source/8&1)<<5 | (1-destination/16&1)<<4 | 3)
		p1 := byte(((^second)&15)<<3 | 0x05)
		p2 := byte(map[int]int{16: 0, 32: 1, 64: 2}[width]<<5 | (1-second/16)<<3)
		return []byte{0x62, p0, p1, p2, 0x44, modRM, immediate}
	}
}

func x86RawCLMULLiteral(encoding string, width int) []byte {
	code := x86RawCLMULCode(encoding, width, 0, 1, 2, 0x11)
	modRMIndex := len(code) - 2
	code[modRMIndex] = 0x15 // RIP+disp32, destination X/Y/Z2.
	code = append(code[:modRMIndex+1], append([]byte{1, 0, 0, 0}, code[modRMIndex+1:]...)...)
	code = append(code, 0xc3)
	for index := 0; index < width; index++ {
		code = append(code, byte(index*9+7))
	}
	return code
}

func TestDecodeX86RawCLMULCompleteRegisterFamily(t *testing.T) {
	for _, encoding := range []string{"legacy", "vex", "evex"} {
		widths := []int{16}
		if encoding != "legacy" {
			widths = append(widths, 32)
		}
		if encoding == "evex" {
			widths = append(widths, 64)
		}
		for _, width := range widths {
			limit := 16
			if encoding == "evex" {
				limit = 32
			}
			for _, source := range []int{0, 7, 8, limit - 1} {
				for _, second := range []int{0, 7, limit - 1} {
					if encoding == "legacy" && second != 0 {
						continue
					}
					for _, destination := range []int{0, 7, limit - 1} {
						name := fmt.Sprintf("%s/%d/%d/%d/%d", encoding, width, source, second, destination)
						t.Run(name, func(t *testing.T) {
							code := x86RawCLMULCode(encoding, width, source, second, destination, 0x11)
							got, length, ok, err := decodedX86RawCLMULInstruction(code, 64)
							if err != nil || !ok || length != len(code) {
								t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
							}
							prefix := "X"
							if width == 32 {
								prefix = "Y"
							} else if width == 64 {
								prefix = "Z"
							}
							want := fmt.Sprintf("VPCLMULQDQ $17, %s%d, %s%d, %s%d", prefix, source, prefix, second, prefix, destination)
							if encoding == "legacy" {
								want = fmt.Sprintf("PCLMULQDQ $17, X%d, X%d", source, destination)
							}
							if got.Raw != want {
								t.Fatalf("decode %x = %q, want %q", code, got.Raw, want)
							}
						})
					}
				}
			}
		}
	}
}

func TestDecodeX86RawCLMULChecksumAVX2Regression(t *testing.T) {
	code := []byte{0xc4, 0xe3, 0x61, 0x44, 0xf4, 0x00, 0xc3}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "checksum crc32c AVX2", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || decoded[0].Raw != "VPCLMULQDQ $0, X4, X3, X6 /* decoded from checksum crc32c AVX2 */" {
		t.Fatalf("decoded %x as %#v", code, decoded)
	}
}

func TestDecodeX86RawCLMULMemoryForms(t *testing.T) {
	for _, encoding := range []string{"legacy", "vex", "evex"} {
		code := x86RawCLMULCode(encoding, 16, 0, 1, 2, 0x11)
		modRMIndex := len(code) - 2
		code[modRMIndex] = 0x54 // disp8(SIB), destination X2.
		code = append(code[:modRMIndex+1], append([]byte{0x88, 0x20}, code[modRMIndex+1:]...)...)
		got, length, ok, err := decodedX86RawCLMULInstruction(code, 64)
		wantOffset := int64(32)
		if encoding == "evex" {
			wantOffset = 512 // EVEX disp8 scales by the 128-bit memory operand.
		}
		if err != nil || !ok || length != len(code) || got.Args[1].Kind != OpMem ||
			got.Args[1].Mem.Base != AX || got.Args[1].Mem.Index != CX ||
			got.Args[1].Mem.Scale != 4 || got.Args[1].Mem.Off != wantOffset {
			t.Fatalf("%s memory source %x decoded as %+v, length=%d, ok=%v, err=%v", encoding, code, got, length, ok, err)
		}
	}
}

func TestDecodeX86RawCLMULRIPDataCompleteFamily(t *testing.T) {
	for _, encoding := range []string{"legacy", "vex", "evex"} {
		widths := []int{16}
		if encoding != "legacy" {
			widths = append(widths, 32)
		}
		if encoding == "evex" {
			widths = append(widths, 64)
		}
		for _, width := range widths {
			name := fmt.Sprintf("%s/%d", encoding, width)
			t.Run(name, func(t *testing.T) {
				code := x86RawCLMULLiteral(encoding, width)
				decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
				if err != nil {
					t.Fatal(err)
				}
				if len(decoded) != 2 || decoded[0].Args[0].Imm != 0x11 ||
					decoded[0].Args[1].Kind != OpSym || !decoded[0].x86RIPLiteral ||
					decoded[1].Op != OpRET ||
					!bytes.Equal(decoded[0].x86RIPLiteralData, code[len(code)-width:]) {
					t.Fatalf("decoded CLMUL literal %x as %#v", code, decoded)
				}
			})
		}
	}
}

func TestDecodeX86RawCLMULRIPDataRejectsUnsafeSources(t *testing.T) {
	for name, mutate := range map[string]func([]byte) []byte{
		"truncated source":        func(code []byte) []byte { return code[:len(code)-1] },
		"outside directive group": func(code []byte) []byte { code[6] = 127; return code },
		"overlapping instruction": func(code []byte) []byte { code[6] = 0; return code },
		"segment override":        func(code []byte) []byte { return append([]byte{0x64}, code...) },
		"address override":        func(code []byte) []byte { return append([]byte{0x67}, code...) },
	} {
		t.Run(name, func(t *testing.T) {
			code := mutate(x86RawCLMULLiteral("evex", 64))
			if _, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{}); err == nil {
				t.Fatalf("accepted unsafe CLMUL literal %x", code)
			}
		})
	}
}

func TestDecodeX86RawCLMULRejectsReservedForms(t *testing.T) {
	valid := x86RawCLMULCode("evex", 64, 0, 1, 2, 0x11)
	for name, mutate := range map[string]func([]byte) []byte{
		"mask":              func(code []byte) []byte { code[3] |= 1; return code },
		"zeroing":           func(code []byte) []byte { code[3] |= 0x80; return code },
		"broadcast":         func(code []byte) []byte { code[3] |= 0x10; return code },
		"width":             func(code []byte) []byte { code[3] |= 0x60; return code },
		"W":                 func(code []byte) []byte { code[2] |= 0x80; return code },
		"address override":  func(code []byte) []byte { return append([]byte{0x67}, code...) },
		"missing immediate": func(code []byte) []byte { return code[:len(code)-1] },
	} {
		t.Run(name, func(t *testing.T) {
			code := mutate(append([]byte(nil), valid...))
			if _, _, ok, err := decodedX86RawCLMULInstruction(code, 64); !ok || err == nil {
				t.Fatalf("accepted reserved CLMUL encoding %x: ok=%v err=%v", code, ok, err)
			}
		})
	}
}

func TestTranslateX86RawCLMULObjects(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for index, encoding := range []string{"legacy", "vex", "evex"} {
		width := []int{16, 32, 64}[index]
		name := fmt.Sprintf("rawCLMUL%d", index)
		fmt.Fprintf(&source, "TEXT %s(SB),$0-0\n", name)
		for _, value := range x86RawCLMULCode(encoding, width, 0, 1, 2, 0x11) {
			fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
		}
		source.WriteString("\tRET\n")
		sigs[name] = FuncSig{Name: name, Ret: Void}
	}
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
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
			ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "raw-clmul.ll", "raw-clmul.o", ir)
		})
	}
}

func TestTranslateX86RawCLMULRIPDataObjects(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for index, encoding := range []string{"legacy", "vex", "evex"} {
		width := []int{16, 32, 64}[index]
		name := fmt.Sprintf("literalCLMUL%d", index)
		fmt.Fprintf(&source, "TEXT %s(SB),$0-0\n", name)
		for _, value := range x86RawCLMULLiteral(encoding, width) {
			fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
		}
		sigs[name] = FuncSig{Name: name, Ret: Void}
	}
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
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
			ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "raw-clmul-literal.ll", "raw-clmul-literal.o", ir)
		})
	}
}
