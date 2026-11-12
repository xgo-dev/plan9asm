package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestX86ADXGrammarMatchesCompleteGoEncoder(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	table := regexp.MustCompile(`(?s)var yml_rl = \[\]ytab\{(.*?)\n\}`).FindStringSubmatch(text)
	if len(table) != 2 || strings.Count(table[1], "argList{") != 1 ||
		!regexp.MustCompile(`\{Zm_r,\s*1,\s*argList\{Yml, Yrl\}\}`).MatchString(table[1]) {
		t.Fatal("Go ADX register/memory operand grammar changed")
	}
	rows := regexp.MustCompile(`\{A((?:ADCX|ADOX)[LQ]),\s*yml_rl,\s*(Pq[45]w?),\s*opBytes\{0xf6\}\}`).FindAllStringSubmatch(text, -1)
	if len(rows) != 4 || len(amd64ADXSpecs) != len(rows) {
		t.Fatal("typed ADX grammar does not match the complete Go encoder family")
	}
	for _, row := range rows {
		spec, ok := amd64ADXSpecs[Op(row[1])]
		bits, prefix, carry := 32, byte(0x66), amd64ADXCarryCF
		if strings.HasSuffix(row[2], "w") {
			bits = 64
		}
		if strings.HasPrefix(row[2], "Pq5") {
			prefix, carry = 0xf3, amd64ADXCarryOF
		}
		if !ok || spec.bits != bits || spec.prefix != prefix || spec.carry != carry {
			t.Fatalf("%s spec %+v does not match Go encoder row %v", row[1], spec, row)
		}
	}
}

func TestX86RawADXEveryRegisterEncoding(t *testing.T) {
	for op, spec := range amd64ADXSpecs {
		for _, mode := range []int{32, 64} {
			if mode == 32 && spec.bits == 64 {
				continue
			}
			registers := 16
			if mode == 32 {
				registers = 8
			}
			for source := 0; source < registers; source++ {
				for destination := 0; destination < registers; destination++ {
					code := []byte{spec.prefix}
					rex := byte(0x40 | source>>3 | (destination>>3)<<2)
					if spec.bits == 64 {
						rex |= 8
					}
					if rex != 0x40 {
						code = append(code, rex)
					}
					code = append(code, 0x0f, 0x38, 0xf6, byte(0xc0|(destination&7)<<3|source&7))
					got, length, _, matched, err := decodeX86RawADX(code, 0, mode)
					wantSource, _ := decodedX86GeneralRegister(source)
					wantDestination, _ := decodedX86GeneralRegister(destination)
					if err != nil || !matched || length != len(code) || got.Op != op ||
						got.Args[0].Reg != wantSource || got.Args[1].Reg != wantDestination {
						t.Fatalf("decode %x mode=%d: %+v error=%v", code, mode, got, err)
					}
				}
			}
		}
	}
}

func TestX86RawADXAddressAndSegmentForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, mode := range []int{32, 64} {
		for _, segment := range []byte{0, 0x64, 0x65} {
			for _, override := range []bool{false, true} {
				for _, prefix := range []byte{0x66, 0xf3} {
					code := []byte{prefix}
					if segment != 0 {
						code = append(code, segment)
					}
					bits := mode
					if override {
						code = append(code, 0x67)
						bits /= 2
					}
					code = append(code, 0x0f, 0x38, 0xf6, 0x18)
					ins, length, _, matched, err := decodeX86RawADX(code, 0, mode)
					if err != nil || !matched || length != len(code) || ins.x86AddressBits != bits || ins.Args[0].Kind != OpMem {
						t.Fatalf("decode %x mode=%d: %+v error=%v", code, mode, ins, err)
					}
					wantSegment := Reg("")
					if segment == 0x64 {
						wantSegment = FS
					} else if segment == 0x65 {
						wantSegment = GS
					}
					if ins.Args[0].Mem.Segment != wantSegment {
						t.Fatalf("segment lost: %+v", ins)
					}
					var source strings.Builder
					source.WriteString("TEXT adxaddress(SB),$0-0\n")
					for _, b := range code {
						fmt.Fprintf(&source, "BYTE $0x%02x\n", b)
					}
					source.WriteString("RET\n")
					arch, triple := "amd64", "x86_64-unknown-linux-gnu"
					if mode == 32 {
						arch, triple = "386", "i386-unknown-linux-gnu"
					}
					ir := x86UnboundVoidRawScalarFormatObject(t, source.String(), arch, triple)
					if override && !strings.Contains(ir, fmt.Sprintf(" to i%d", bits)) {
						t.Fatal("address-size wrapping was not lowered")
					}
					compileLLVMToObject(t, llc, triple, "adx-address.ll", "adx-address.o", ir)
				}
			}
		}
	}
}

func TestX86RawADXSourceLocalRIPAndInvalidEncodings(t *testing.T) {
	for op, spec := range amd64ADXSpecs {
		code := []byte{spec.prefix}
		if spec.bits == 64 {
			code = append(code, 0x48)
		}
		code = append(code, 0x0f, 0x38, 0xf6, 0x1d, 1, 0, 0, 0, 0xc3)
		for i := 0; i < spec.bits/8; i++ {
			code = append(code, byte(i+1))
		}
		decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, string(op), map[string]bool{})
		if err != nil || len(decoded) != 2 || decoded[0].Op != op || len(decoded[0].x86RIPLiteralData) != spec.bits/8 {
			t.Fatalf("source-local literal %x: %+v error=%v", code, decoded, err)
		}
		if _, err := decodeX86RawDirectiveGroup(code[:len(code)-1], 64, 0, "truncated literal", map[string]bool{}); err == nil {
			t.Fatal("accepted incomplete literal")
		}
	}
	for _, code := range [][]byte{
		{0xf0, 0x66, 0x0f, 0x38, 0xf6, 0xc0},
		{0x66, 0x0f, 0x38, 0xf6},
		{0xf3, 0x0f, 0x38, 0xf6, 0x04},
		{0x66, 0x0f, 0x38, 0xf6, 0x80},
		append([]byte{0x66}, append([]byte(strings.Repeat("\x67", 11)), 0x0f, 0x38, 0xf6, 0xc0)...),
	} {
		if _, _, _, matched, err := decodeX86RawADX(code, 0, 64); !matched || err == nil {
			t.Fatalf("accepted invalid ADX %x", code)
		}
	}
}

func TestX86RawADXCompleteRegisterAndMemoryForms(t *testing.T) {
	for _, mode := range []int{32, 64} {
		for _, prefix := range []byte{0x66, 0xf3} {
			for _, bits := range []int{32, 64} {
				if mode == 32 && bits == 64 {
					continue
				}
				for _, form := range []struct {
					name   string
					modrm  []byte
					source string
				}{
					{"register", []byte{0xd8}, "AX"},
					{"memory", []byte{0x58, 0x20}, "32(AX)"},
					{"indexed", []byte{0x5c, 0x88, 0xf0}, "-16(AX)(CX*4)"},
				} {
					name := fmt.Sprintf("mode%d/prefix%x/bits%d/%s", mode, prefix, bits, form.name)
					t.Run(name, func(t *testing.T) {
						code := []byte{prefix}
						if bits == 64 {
							code = append(code, 0x48)
						}
						code = append(code, 0x0f, 0x38, 0xf6)
						code = append(code, form.modrm...)
						code = append(code, 0xc3)
						decoded, err := decodeX86RawDirectiveGroup(code, mode, 0, name, map[string]bool{})
						if err != nil {
							t.Fatal(err)
						}
						stem, width := "ADCX", "L"
						if prefix == 0xf3 {
							stem = "ADOX"
						}
						if bits == 64 {
							width = "Q"
						}
						if len(decoded) != 2 || decoded[0].Op != Op(stem+width) || decoded[1].Op != OpRET ||
							len(decoded[0].Args) != 2 || decoded[0].Args[0].String() != form.source || decoded[0].Args[1].Reg != BX {
							t.Fatalf("decoded %x as %+v, want %s%s %s, BX; RET", code, decoded, stem, width, form.source)
						}
					})
				}
			}
		}
	}
}

func TestX86RawADXExtendedRegistersFromEthereum(t *testing.T) {
	for _, form := range []struct {
		code                []byte
		op                  Op
		source, destination Reg
	}{
		{[]byte{0x66, 0x4c, 0x0f, 0x38, 0xf6, 0xc8}, "ADCXQ", AX, "R9"},
		{[]byte{0xf3, 0x4c, 0x0f, 0x38, 0xf6, 0xd3}, "ADOXQ", BX, "R10"},
		{[]byte{0x66, 0x4d, 0x0f, 0x38, 0xf6, 0xe7}, "ADCXQ", "R15", "R12"},
	} {
		code := append(append([]byte(nil), form.code...), 0xc3)
		decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "Ethereum ADX", map[string]bool{})
		if err != nil {
			t.Fatal(err)
		}
		if len(decoded) != 2 || decoded[0].Op != form.op ||
			decoded[0].Args[0].Reg != form.source || decoded[0].Args[1].Reg != form.destination {
			t.Fatalf("decoded %x as %+v", code, decoded)
		}
	}
}

func TestX86RawADXObjectsAcrossTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-apple-darwin"},
		{"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-pc-windows-msvc"},
		{"386", "i386-unknown-linux-gnu"},
		{"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT adxraw(SB),$0-0\n")
			for _, prefix := range []byte{0x66, 0xf3} {
				for _, rex := range []byte{0, 0x48} {
					if target.arch == "386" && rex != 0 {
						continue
					}
					for _, modrm := range [][]byte{{0xd8}, {0x58, 0x20}, {0x5c, 0x88, 0xf0}} {
						code := []byte{prefix}
						if rex != 0 {
							code = append(code, rex)
						}
						code = append(code, 0x0f, 0x38, 0xf6)
						code = append(code, modrm...)
						for _, value := range code {
							fmt.Fprintf(&source, "BYTE $0x%02x\n", value)
						}
					}
				}
			}
			source.WriteString("RET\n")
			requireX86GoAssemblerResult(t, target.arch, source.String(), true)
			ir := x86UnboundVoidRawScalarFormatObject(t, source.String(), target.arch, target.triple)
			compileLLVMToObject(t, llc, target.triple, "adx-raw.ll", "adx-raw.o", ir)
		})
	}
}
