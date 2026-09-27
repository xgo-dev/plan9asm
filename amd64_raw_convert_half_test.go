package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeX86RawVEXHalfConversion(form x86RawHalfConversionForm, width256 bool, reg, rm int, memory bool, immediate byte) []byte {
	if memory {
		rm = 0
	}
	l := byte(0)
	if width256 {
		l = 1
	}
	p0 := byte((1-reg/8)<<7 | 1<<6 | (1-rm/8)<<5 | form.mapNumber)
	p1 := byte(0x79 | l<<2)
	modRM := byte(0xc0 | (reg&7)<<3 | rm&7)
	if memory {
		modRM = byte(0x40 | (reg&7)<<3)
	}
	code := []byte{0xc4, p0, p1, byte(form.opcode), modRM}
	if memory {
		code = append(code, 7)
	}
	if form.immediate {
		code = append(code, immediate)
	}
	return code
}

func encodeX86RawEVEXHalfConversion(form x86RawHalfConversionForm, vectorBits, mask int, zeroing, sae bool, reg, rm int, memory bool, immediate byte) []byte {
	if memory {
		rm = 0
	}
	p0 := byte((1-reg/8&1)<<7 | (1-rm/16)<<6 | (1-rm/8&1)<<5 | (1-reg/16)<<4 | form.mapNumber)
	p2 := byte(vectorBits<<5 | 0x08 | mask)
	if zeroing {
		p2 |= 0x80
	}
	if sae {
		p2 |= 0x10
	}
	modRM := byte(0xc0 | (reg&7)<<3 | rm&7)
	if memory {
		modRM = byte(0x40 | (reg&7)<<3)
	}
	code := []byte{0x62, p0, 0x7d, p2, byte(form.opcode), modRM}
	if memory {
		code = append(code, 7)
	}
	if form.immediate {
		code = append(code, immediate)
	}
	return code
}

func TestTranslateRawHalfConversionGorseRegression(t *testing.T) {
	const source = `TEXT rawHalfToSingle(SB), $0-0
	LONG $0x137da2c4
	WORD $0x474c
	BYTE $0xf0
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch:       "amd64",
		TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs:         map[string]FuncSig{"rawHalfToSingle": {Name: "rawHalfToSingle", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "fpext <8 x half>") {
		t.Fatalf("raw VCVTPH2PS omitted half-to-single conversion:\n%s", ir)
	}
}

func TestDecodedX86PackedHalfConversionGorseEVEXMemory(t *testing.T) {
	cases := []struct {
		name string
		code []byte
		want MemRef
	}{
		{
			name: "SIB",
			code: []byte{0x62, 0xf2, 0x7d, 0x48, 0x13, 0x0c, 0x4f},
			want: MemRef{Base: DI, Index: CX, Scale: 2},
		},
		{
			name: "SIB compressed displacement",
			code: []byte{0x62, 0xf2, 0x7d, 0x48, 0x13, 0x4c, 0x4f, 0x01},
			want: MemRef{Base: DI, Index: CX, Scale: 2, Off: 32},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, length, matched, err := decodedX86PackedHalfConversionInstruction(tc.code, 64)
			if err != nil || !matched || length != len(tc.code) || got.Op != "VCVTPH2PS" {
				t.Fatalf("decode %x = %+v length=%d matched=%v err=%v", tc.code, got, length, matched, err)
			}
			if len(got.Args) != 2 || got.Args[0].Kind != OpMem || got.Args[0].Mem != tc.want || got.Args[1].Reg != "Z1" {
				t.Fatalf("decode %x = %+v, want memory %+v and Z1", tc.code, got, tc.want)
			}
		})
	}
}

func TestDecodedX86PackedHalfConversionGoRowsAndWidths(t *testing.T) {
	if len(x86RawHalfConversionForms) != 4 ||
		x86RawHalfConversionForms[0] != (x86RawHalfConversionForm{op: "VCVTPH2PS", mapNumber: 2, opcode: 0x13}) ||
		x86RawHalfConversionForms[1] != (x86RawHalfConversionForm{op: "VCVTPS2PH", mapNumber: 3, opcode: 0x1d, immediate: true}) {
		t.Fatalf("packed half conversion grammar does not match the two Go 1.27 opcode rows")
	}
	for _, form := range x86RawHalfConversionForms[:2] {
		for _, width256 := range []bool{false, true} {
			vector := "X"
			if width256 {
				vector = "Y"
			}
			for _, memory := range []bool{false, true} {
				code := encodeX86RawVEXHalfConversion(form, width256, 2, 1, memory, 7)
				got, length, matched, err := decodedX86PackedHalfConversionInstruction(code, 64)
				if err != nil || !matched || length != len(code) || got.Op != form.op {
					t.Fatalf("VEX %x = %+v length=%d matched=%v err=%v", code, got, length, matched, err)
				}
				if form.immediate {
					if len(got.Args) != 3 || got.Args[0].String() != "$7" || got.Args[1].String() != vector+"2" {
						t.Fatalf("VEX single-to-half %x = %+v", code, got)
					}
				} else if len(got.Args) != 2 || got.Args[1].String() != vector+"2" {
					t.Fatalf("VEX half-to-single %x = %+v", code, got)
				}
			}
		}
		for vectorBits, vector := range []string{"X", "Y", "Z"} {
			for _, memory := range []bool{false, true} {
				for _, masked := range []bool{false, true} {
					mask := 0
					if masked {
						mask = 3
					}
					code := encodeX86RawEVEXHalfConversion(form, vectorBits, mask, masked && !memory, false, 21, 20, memory, 9)
					got, length, matched, err := decodedX86PackedHalfConversionInstruction(code, 64)
					if err != nil || !matched || length != len(code) {
						t.Fatalf("EVEX %x = %+v length=%d matched=%v err=%v", code, got, length, matched, err)
					}
					wantOp := form.op
					if masked && !memory {
						wantOp += ".Z"
					}
					if got.Op != wantOp {
						t.Fatalf("EVEX %x op=%s, want %s", code, got.Op, wantOp)
					}
					registerIndex := 1
					if !form.immediate {
						registerIndex = len(got.Args) - 1
					}
					if got.Args[registerIndex].String() != fmt.Sprintf("%s21", vector) {
						t.Fatalf("EVEX %x = %+v, lost high register", code, got)
					}
				}
			}
		}
	}
}

func TestDecodedX86PackedHalfConversionSAEAndInvalidForms(t *testing.T) {
	for _, form := range x86RawHalfConversionForms[:2] {
		code := encodeX86RawEVEXHalfConversion(form, 2, 2, true, true, 1, 2, false, 7)
		got, length, matched, err := decodedX86PackedHalfConversionInstruction(code, 64)
		if err != nil || !matched || length != len(code) || got.Op != form.op+".SAE.Z" {
			t.Fatalf("SAE %x = %+v length=%d matched=%v err=%v", code, got, length, matched, err)
		}
		invalid := append([]byte(nil), code...)
		invalid[2] |= 0x80
		if _, _, matched, err := decodedX86PackedHalfConversionInstruction(invalid, 64); !matched || err == nil {
			t.Fatalf("W=1 encoding accepted: %x", invalid)
		}
		invalid = append([]byte(nil), code...)
		invalid[3] &^= 7
		if _, _, matched, err := decodedX86PackedHalfConversionInstruction(invalid, 64); !matched || err == nil {
			t.Fatalf("zeroing without mask accepted: %x", invalid)
		}
	}
	toHalf := x86RawHalfConversionForms[1]
	missingImmediate := encodeX86RawVEXHalfConversion(toHalf, false, 1, 2, false, 7)
	missingImmediate = missingImmediate[:len(missingImmediate)-1]
	if _, _, matched, err := decodedX86PackedHalfConversionInstruction(missingImmediate, 64); !matched || err == nil {
		t.Fatalf("missing imm8 accepted: %x", missingImmediate)
	}
	fromHalf := x86RawHalfConversionForms[0]
	invalidMemorySAE := encodeX86RawEVEXHalfConversion(fromHalf, 2, 0, false, true, 1, 0, true, 0)
	if _, _, matched, err := decodedX86PackedHalfConversionInstruction(invalidMemorySAE, 64); !matched || err == nil {
		t.Fatalf("half-to-single memory SAE accepted: %x", invalidMemorySAE)
	}
}

func TestTranslateRawPackedHalfConversionLLVM22Targets(t *testing.T) {
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
			source.WriteString("TEXT rawPackedHalfConversions(SB), $0-0\n")
			appendBytes := func(code []byte) {
				for _, value := range code {
					fmt.Fprintf(&source, "\tBYTE $0x%02x\n", value)
				}
			}
			for _, form := range x86RawHalfConversionForms[:2] {
				for _, width256 := range []bool{false, true} {
					appendBytes(encodeX86RawVEXHalfConversion(form, width256, 2, 1, false, 7))
					appendBytes(encodeX86RawVEXHalfConversion(form, width256, 2, 0, true, 7))
				}
				for vectorBits := 0; vectorBits < 3; vectorBits++ {
					mask := 3
					if target.goarch == "386" && form.immediate {
						mask = 0
					}
					reg, rm := 21, 20
					if target.goarch == "386" {
						reg, rm = 2, 1
					}
					appendBytes(encodeX86RawEVEXHalfConversion(form, vectorBits, mask, mask != 0, vectorBits == 2, reg, rm, false, 9))
					appendBytes(encodeX86RawEVEXHalfConversion(form, vectorBits, mask, false, false, 1, 0, true, 9))
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
				Sigs:         map[string]FuncSig{"rawPackedHalfConversions": {Name: "rawPackedHalfConversions", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, "fpext <") || !strings.Contains(ir, "fptrunc <") {
				t.Fatalf("raw half-conversion family was not lowered:\n%s", ir)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-half-conversions.ll", "raw-half-conversions.o", ir)
		})
	}
}
