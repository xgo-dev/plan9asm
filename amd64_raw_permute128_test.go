package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeX86RawVPERM2X128(opcode, immediate byte, first, second, destination int) []byte {
	p0 := byte((1-destination/8)<<7 | 1<<6 | (1-first/8)<<5 | 3)
	p1 := byte((^second&15)<<3 | 5)
	modRM := byte(0xc0 | destination&7<<3 | first&7)
	return []byte{0xc4, p0, p1, opcode, modRM, immediate}
}

func TestDecodeX86RawDirectiveGroupReportedPsiphonVPERM2I128(t *testing.T) {
	code := []byte{0xc4, 0xe3, 0x6d, 0x46, 0xc3, 0x20}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "Psiphon VPERM2I128 sequence", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	const want = "VPERM2I128 $32, Y3, Y2, Y0"
	if len(decoded) != 1 || !strings.HasPrefix(decoded[0].Raw, want+" ") {
		t.Fatalf("decoded %x as %#v, want %q", code, decoded, want)
	}
}

func TestDecodedX86RawVPERM2X128CompleteRegisterFamily(t *testing.T) {
	count := 0
	for _, operation := range []struct {
		opcode byte
		name   string
	}{
		{opcode: 0x06, name: "VPERM2F128"},
		{opcode: 0x46, name: "VPERM2I128"},
	} {
		for first := 0; first < 16; first++ {
			for second := 0; second < 16; second++ {
				for destination := 0; destination < 16; destination++ {
					immediate := byte(first*16 + destination)
					code := encodeX86RawVPERM2X128(operation.opcode, immediate, first, second, destination)
					got, length, ok, err := decodedX86Permute128Instruction(code, 64)
					want := fmt.Sprintf("%s $%d, Y%d, Y%d, Y%d", operation.name, immediate, first, second, destination)
					if err != nil || !ok || length != len(code) || got.Raw != want {
						t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v; want %q", code, got, length, ok, err, want)
					}
					count++
				}
			}
		}
	}
	if count != 8192 {
		t.Fatalf("covered %d VPERM2F128/VPERM2I128 register encodings, want 8192", count)
	}
}

func TestDecodedX86RawVPERM2X128MemoryAndInvalidForms(t *testing.T) {
	for _, test := range []struct {
		name string
		code []byte
		want string
	}{
		{
			name: "VPERM2F128 extended SIB",
			code: []byte{0x65, 0xc4, 0x03, 0x15, 0x06, 0x64, 0x8b, 0x20, 0xff},
			want: "VPERM2F128 $255, 32(R11)(R9*4)(GS), Y13, Y12",
		},
		{
			name: "VPERM2I128 extended SIB",
			code: []byte{0x64, 0xc4, 0x03, 0x15, 0x46, 0x64, 0x8b, 0x20, 0xfe},
			want: "VPERM2I128 $254, 32(R11)(R9*4)(FS), Y13, Y12",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, length, ok, err := decodedX86Permute128Instruction(test.code, 64)
			if err != nil || !ok || length != len(test.code) || got.Raw != test.want {
				t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v; want %q", test.code, got, length, ok, err, test.want)
			}
		})
	}

	for _, test := range []struct {
		name     string
		mode     int
		encoding []byte
		wantOK   bool
	}{
		{name: "386 operand limit", mode: 32, encoding: encodeX86RawVPERM2X128(0x46, 1, 0, 1, 2), wantOK: true},
		{name: "wrong pp", mode: 64, encoding: []byte{0xc4, 0xe3, 0x6c, 0x46, 0xc3, 4}, wantOK: true},
		{name: "W", mode: 64, encoding: []byte{0xc4, 0xe3, 0xed, 0x46, 0xc3, 4}, wantOK: true},
		{name: "128-bit vector length", mode: 64, encoding: []byte{0xc4, 0xe3, 0x69, 0x46, 0xc3, 4}, wantOK: true},
		{name: "truncated immediate", mode: 64, encoding: []byte{0xc4, 0xe3, 0x6d, 0x46, 0xc3}, wantOK: true},
		{name: "address override", mode: 64, encoding: []byte{0x67, 0xc4, 0xe3, 0x6d, 0x46, 0xc3, 4}, wantOK: true},
		{name: "legacy prefix", mode: 64, encoding: []byte{0x66, 0xc4, 0xe3, 0x6d, 0x46, 0xc3, 4}},
		{name: "wrong opcode", mode: 64, encoding: []byte{0xc4, 0xe3, 0x6d, 0x47, 0xc3, 4}},
		{name: "wrong map", mode: 64, encoding: []byte{0xc4, 0xe2, 0x6d, 0x46, 0xc3, 4}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, ok, err := decodedX86Permute128Instruction(test.encoding, test.mode)
			if ok != test.wantOK {
				t.Fatalf("encoding %x returned ok=%v err=%v, want ok=%v", test.encoding, ok, err, test.wantOK)
			}
			if test.wantOK && err == nil {
				t.Fatalf("invalid encoding %x was accepted", test.encoding)
			}
			if !test.wantOK && err != nil {
				t.Fatalf("unrelated encoding %x returned err=%v", test.encoding, err)
			}
		})
	}
}
