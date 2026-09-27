package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeX86RawPackedSAD(op Op, vectorBits, first, second, destination, mask int, zero, memory bool) []byte {
	if memory {
		first = 0
	}
	mapNumber, opcode := byte(1), byte(0xf6)
	if op != "VPSADBW" && op != "VPSADBW.EVEX" {
		mapNumber, opcode = 3, 0x42
	}
	modRM := byte(0xc0 | destination&7<<3 | first&7)
	if memory {
		modRM = byte(0x40 | destination&7<<3)
	}
	var code []byte
	if op == "VDBPSADBW" || op == "VPSADBW.EVEX" {
		p0 := byte((1-destination/8&1)<<7 | (1-first/16)<<6 |
			(1-first/8&1)<<5 | (1-destination/16)<<4 | int(mapNumber))
		p1 := byte((^second&15)<<3 | 4 | 1)
		p2 := byte(vectorBits<<5 | (1-second/16)<<3 | mask)
		if zero {
			p2 |= 0x80
		}
		code = []byte{0x62, p0, p1, p2, opcode, modRM}
	} else {
		p0 := byte((1-destination/8&1)<<7 | 1<<6 |
			(1-first/8&1)<<5 | int(mapNumber))
		p1 := byte((^second&15)<<3 | vectorBits<<2 | 1)
		code = []byte{0xc4, p0, p1, opcode, modRM}
	}
	if memory {
		code = append(code, 1)
	}
	if op != "VPSADBW" && op != "VPSADBW.EVEX" {
		code = append(code, 0x39)
	}
	return code
}

func TestTranslateRawPackedSADGorseRegression(t *testing.T) {
	const source = `TEXT rawPackedSAD(SB), $0-0
	LONG $0xd3f6edc5
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{
		Goarch:       "amd64",
		TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs:         map[string]FuncSig{"rawPackedSAD": {Name: "rawPackedSAD", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTranslateRawPackedSADLegacyForms(t *testing.T) {
	const source = `TEXT rawLegacySAD(SB), $0-0
	BYTE $0x66; BYTE $0x0f; BYTE $0xf6; BYTE $0xc1
	BYTE $0x66; BYTE $0x0f; BYTE $0x3a; BYTE $0x42; BYTE $0xc1; BYTE $0x01
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{
		Goarch:       "amd64",
		TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs:         map[string]FuncSig{"rawLegacySAD": {Name: "rawLegacySAD", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDecodedX86RawPackedSADGoRows(t *testing.T) {
	for _, test := range []struct {
		encoded Op
		want    Op
		widths  int
	}{
		{"VPSADBW", "VPSADBW", 2},
		{"VPSADBW.EVEX", "VPSADBW", 3},
		{"VMPSADBW", "VMPSADBW", 2},
		{"VDBPSADBW", "VDBPSADBW", 3},
	} {
		if _, ok := amd64PackedSADSpecs[test.want]; !ok {
			t.Fatalf("missing lowerer for Go row %s", test.want)
		}
		for vectorBits := 0; vectorBits < test.widths; vectorBits++ {
			for _, memory := range []bool{false, true} {
				for _, mask := range []int{0, 3} {
					if mask != 0 && test.encoded != "VDBPSADBW" {
						continue
					}
					for _, zero := range []bool{false, true} {
						if zero && mask == 0 {
							continue
						}
						code := encodeX86RawPackedSAD(test.encoded, vectorBits, 4, 5, 2, mask, zero, memory)
						got, length, recognized, err := decodedX86RawPackedSADInstruction(code, 64)
						if err != nil || !recognized || length != len(code) {
							t.Fatalf("decode %x: %+v length=%d recognized=%v err=%v", code, got, length, recognized, err)
						}
						wantOp := test.want
						if zero {
							wantOp += ".Z"
						}
						if got.Op != wantOp || got.Args[len(got.Args)-1].String() != fmt.Sprintf("%s2", "XYZ"[vectorBits:vectorBits+1]) {
							t.Fatalf("decode %x: %+v, want %s", code, got, wantOp)
						}
						if memory {
							firstIndex := 0
							if test.want != "VPSADBW" {
								firstIndex = 1
							}
							if got.Args[firstIndex].Kind != OpMem {
								t.Fatalf("decode %x did not retain memory: %+v", code, got)
							}
						}
					}
				}
			}
		}
	}
}

func TestDecodedX86RawPackedSADRejectsInvalidForms(t *testing.T) {
	base := encodeX86RawPackedSAD("VPSADBW", 1, 1, 2, 3, 0, false, false)
	for _, test := range []struct {
		name string
		code []byte
	}{
		{"VEX W1", []byte{base[0], base[1], base[2] | 0x80, base[3], base[4]}},
		{"missing ModRM", base[:4]},
		{"address override", append([]byte{0x67}, base...)},
		{"missing immediate", encodeX86RawPackedSAD("VMPSADBW", 0, 1, 2, 3, 0, false, false)[:5]},
		{"VDB broadcast", func() []byte {
			code := encodeX86RawPackedSAD("VDBPSADBW", 0, 0, 2, 3, 0, false, true)
			code[3] |= 0x10
			return code
		}()},
		{"VPSADBW writemask", func() []byte {
			code := encodeX86RawPackedSAD("VPSADBW.EVEX", 0, 1, 2, 3, 0, false, false)
			code[3] |= 3
			return code
		}()},
		{"VDB zero without mask", encodeX86RawPackedSAD("VDBPSADBW", 0, 1, 2, 3, 0, true, false)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, recognized, err := decodedX86RawPackedSADInstruction(test.code, 64); !recognized || err == nil {
				t.Fatalf("accepted invalid %x: recognized=%v err=%v", test.code, recognized, err)
			}
		})
	}
}

func TestTranslateRawPackedSADLLVM22Targets(t *testing.T) {
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
			source.WriteString("TEXT rawPackedSADFamily(SB), $0-0\n")
			for _, test := range []struct {
				op     Op
				width  int
				mask   int
				zero   bool
				memory bool
			}{
				{op: "VPSADBW", width: 1},
				{op: "VPSADBW.EVEX", width: 2, memory: true},
				{op: "VMPSADBW", width: 1, memory: true},
				{op: "VDBPSADBW", width: 2, mask: 3, zero: true, memory: true},
			} {
				code := encodeX86RawPackedSAD(
					test.op, test.width, 1, 2, 3, test.mask, test.zero, test.memory,
				)
				for _, value := range code {
					fmt.Fprintf(&source, "\tBYTE $0x%02x\n", value)
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
				Sigs:         map[string]FuncSig{"rawPackedSADFamily": {Name: "rawPackedSADFamily", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-packed-sad.ll", "raw-packed-sad.o", ir)
		})
	}
}
