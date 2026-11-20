package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeX86RawVectorBitCount(form x86RawVectorBitCountForm, vectorBits, destination, source, mask int, zeroing, broadcast, memory bool) []byte {
	if memory {
		source = 0
	}
	p0 := byte((1-destination/8&1)<<7 | (1-source/16)<<6 |
		(1-source/8&1)<<5 | (1-destination/16)<<4 | 2)
	p1 := byte(0x7d)
	if form.w {
		p1 |= 0x80
	}
	p2 := byte(vectorBits<<5 | 0x08 | mask)
	if zeroing {
		p2 |= 0x80
	}
	if broadcast {
		p2 |= 0x10
	}
	modRM := byte(0xc0 | (destination&7)<<3 | source&7)
	if memory {
		modRM = byte(0x40 | (destination&7)<<3)
	}
	code := []byte{0x62, p0, p1, p2, byte(form.opcode), modRM}
	if memory {
		code = append(code, 1)
	}
	return code
}

func TestTranslateRawBitCountGorseRegression(t *testing.T) {
	const source = `TEXT rawVectorPopcount(SB), $0-0
	LONG $0x48fdf262
	WORD $0xdb55
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch:       "amd64",
		TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs:         map[string]FuncSig{"rawVectorPopcount": {Name: "rawVectorPopcount", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "llvm.ctpop.v8i64") {
		t.Fatalf("raw VPOPCNTQ omitted eight-lane population count:\n%s", ir)
	}
}

func TestDecodedX86RawVectorBitCountCompleteGoRows(t *testing.T) {
	if len(x86RawVectorBitCountForms) != len(amd64PackedBitCountSpecs) {
		t.Fatalf("raw bit-count grammar has %d rows, named lowerer has %d", len(x86RawVectorBitCountForms), len(amd64PackedBitCountSpecs))
	}
	seen := make(map[Op]bool)
	for _, form := range x86RawVectorBitCountForms {
		spec, ok := amd64PackedBitCountSpecs[form.op]
		if !ok || seen[form.op] {
			t.Fatalf("missing or duplicated bit-count spec for %s", form.op)
		}
		seen[form.op] = true
		for vectorBits, prefix := range [...]string{"X", "Y", "Z"} {
			vectorBytes := 16 << vectorBits
			for _, memory := range []bool{false, true} {
				for _, masked := range []bool{false, true} {
					mask := 0
					if masked {
						mask = 3
					}
					for _, zeroing := range []bool{false, true} {
						if zeroing && !masked {
							continue
						}
						for _, broadcast := range []bool{false, true} {
							if broadcast && (!memory || !spec.broadcast) {
								continue
							}
							code := encodeX86RawVectorBitCount(form, vectorBits, 21, 20, mask, zeroing, broadcast, memory)
							got, length, recognized, err := decodedX86RawVectorBitCountInstruction(code, 64)
							if err != nil || !recognized || length != len(code) {
								t.Fatalf("decode %x = %+v length=%d recognized=%v err=%v", code, got, length, recognized, err)
							}
							wantOp := form.op
							if broadcast {
								wantOp += ".BCST"
							}
							if zeroing {
								wantOp += ".Z"
							}
							if got.Op != wantOp || got.Args[len(got.Args)-1].String() != fmt.Sprintf("%s21", prefix) {
								t.Fatalf("decode %x = %+v, want %s and %s21", code, got, wantOp, prefix)
							}
							if masked && (len(got.Args) != 3 || got.Args[1].String() != "K3") || !masked && len(got.Args) != 2 {
								t.Fatalf("decode %x = %+v, lost mask", code, got)
							}
							source := got.Args[0]
							if memory {
								wantBytes := vectorBytes
								if broadcast {
									wantBytes = spec.laneBits / 8
								}
								if source.Kind != OpMem || source.Mem.Base != AX || source.Mem.Off != int64(wantBytes) {
									t.Fatalf("decode %x = %+v, want compressed displacement %d", code, got, wantBytes)
								}
							} else if source.String() != fmt.Sprintf("%s20", prefix) {
								t.Fatalf("decode %x = %+v, want %s20", code, got, prefix)
							}
						}
					}
				}
			}
		}
	}
}

func TestDecodedX86RawVectorBitCountRejectsReservedBits(t *testing.T) {
	form := x86RawVectorBitCountForms[5]
	base := encodeX86RawVectorBitCount(form, 2, 2, 1, 3, true, false, false)
	for _, test := range []struct {
		name string
		code []byte
	}{
		{"fixed bit", []byte{base[0], base[1], base[2] &^ 4, base[3], base[4], base[5]}},
		{"vvvv", []byte{base[0], base[1], base[2] &^ 8, base[3], base[4], base[5]}},
		{"V prime", []byte{base[0], base[1], base[2], base[3] &^ 8, base[4], base[5]}},
		{"reserved length", []byte{base[0], base[1], base[2], base[3] | 0x20, base[4], base[5]}},
		{"zero without mask", []byte{base[0], base[1], base[2], base[3] &^ 7, base[4], base[5]}},
		{"register broadcast", []byte{base[0], base[1], base[2], base[3] | 0x10, base[4], base[5]}},
		{"missing ModRM", base[:5]},
		{"address override", append([]byte{0x67}, base...)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, recognized, err := decodedX86RawVectorBitCountInstruction(test.code, 64); !recognized || err == nil {
				t.Fatalf("accepted reserved encoding %x: recognized=%v err=%v", test.code, recognized, err)
			}
		})
	}
	broadcastWord := encodeX86RawVectorBitCount(x86RawVectorBitCountForms[3], 2, 2, 0, 0, false, true, true)
	if _, _, recognized, err := decodedX86RawVectorBitCountInstruction(broadcastWord, 64); !recognized || err == nil {
		t.Fatalf("accepted VPOPCNTW broadcast %x", broadcastWord)
	}
}

func TestTranslateRawVectorBitCountLLVM22Targets(t *testing.T) {
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
			source.WriteString("TEXT rawBitCountFamily(SB), $0-0\n")
			appendBytes := func(code []byte) {
				for _, value := range code {
					fmt.Fprintf(&source, "\tBYTE $0x%02x\n", value)
				}
			}
			for _, form := range x86RawVectorBitCountForms {
				for vectorBits := 0; vectorBits < 3; vectorBits++ {
					appendBytes(encodeX86RawVectorBitCount(form, vectorBits, 2, 1, 0, false, false, false))
					appendBytes(encodeX86RawVectorBitCount(form, vectorBits, 2, 0, 3, true, false, true))
					if amd64PackedBitCountSpecs[form.op].broadcast {
						appendBytes(encodeX86RawVectorBitCount(form, vectorBits, 2, 0, 4, false, true, true))
					}
				}
			}
			source.WriteString("\tRET\n")
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs:         map[string]FuncSig{"rawBitCountFamily": {Name: "rawBitCountFamily", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, "llvm.ctpop") || !strings.Contains(ir, "llvm.ctlz") {
				t.Fatalf("raw vector bit-count family omitted operations:\n%s", ir)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-vector-bit-count.ll", "raw-vector-bit-count.o", ir)
		})
	}
}
