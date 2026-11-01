package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeX86RawPALIGNR(immediate byte, mode, source, destination int) []byte {
	code := []byte{0x66}
	if mode == 64 {
		code = append(code, byte(0x40|destination/8<<2|source/8))
	}
	modRM := byte(0xc0 | destination&7<<3 | source&7)
	return append(code, 0x0f, 0x3a, 0x0f, modRM, immediate)
}

func encodeX86RawVEXVPALIGNR(immediate byte, wide bool, first, second, destination int) []byte {
	p0 := byte((1-destination/8)<<7 | 1<<6 | (1-first/8)<<5 | 3)
	p1 := byte((^second&15)<<3 | 1)
	if wide {
		p1 |= 4
	}
	modRM := byte(0xc0 | destination&7<<3 | first&7)
	return []byte{0xc4, p0, p1, 0x0f, modRM, immediate}
}

func encodeX86RawEVEXVPALIGNR(immediate, vectorBits byte, mask int, zeroing bool, first, second, destination int) []byte {
	p0 := byte((^destination>>3)&1)<<7 |
		byte((^first>>4)&1)<<6 |
		byte((^first>>3)&1)<<5 |
		byte((^destination>>4)&1)<<4 | 3
	p1 := byte(^second&15)<<3 | 5
	p2 := vectorBits<<5 | byte((^second>>4)&1)<<3 | byte(mask)
	if zeroing {
		p2 |= 0x80
	}
	modRM := byte(0xc0 | destination&7<<3 | first&7)
	return []byte{0x62, p0, p1, p2, 0x0f, modRM, immediate}
}

func TestDecodeX86RawDirectiveGroupReportedIPFSVPALIGNR(t *testing.T) {
	code := []byte{0xc4, 0xe3, 0x41, 0x0f, 0xc6, 0x04}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "IPFS VPALIGNR sequence", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	const want = "VPALIGNR $4, X6, X7, X0"
	if len(decoded) != 1 || !strings.HasPrefix(decoded[0].Raw, want+" ") {
		t.Fatalf("decoded %x as %#v, want %q", code, decoded, want)
	}
}

func TestDecodedX86RawPALIGNRCompleteRegisterFamily(t *testing.T) {
	count := 0
	for _, mode := range []int{32, 64} {
		registers := 8
		if mode == 64 {
			registers = 16
		}
		for source := 0; source < registers; source++ {
			for destination := 0; destination < registers; destination++ {
				immediate := byte(source*16 + destination)
				code := encodeX86RawPALIGNR(immediate, mode, source, destination)
				got, length, ok, err := decodedX86PackedAlignRightInstruction(code, mode)
				want := fmt.Sprintf("PALIGNR $%d, X%d, X%d", immediate, source, destination)
				if err != nil || !ok || length != len(code) || got.Raw != want {
					t.Fatalf("decode mode=%d %x = %+v, length=%d, ok=%v, err=%v; want %q", mode, code, got, length, ok, err, want)
				}
				count++
			}
		}
	}
	if count != 320 {
		t.Fatalf("covered %d PALIGNR register encodings, want 320", count)
	}
}

func TestDecodedX86RawVPALIGNRCompleteVEXRegisterFamily(t *testing.T) {
	count := 0
	for _, wide := range []bool{false, true} {
		vectorName := "X"
		if wide {
			vectorName = "Y"
		}
		for first := 0; first < 16; first++ {
			for second := 0; second < 16; second++ {
				for destination := 0; destination < 16; destination++ {
					immediate := byte(first*16 + destination)
					code := encodeX86RawVEXVPALIGNR(immediate, wide, first, second, destination)
					got, length, ok, err := decodedX86PackedAlignRightInstruction(code, 64)
					want := fmt.Sprintf("VPALIGNR $%d, %s%d, %s%d, %s%d", immediate, vectorName, first, vectorName, second, vectorName, destination)
					if err != nil || !ok || length != len(code) || got.Raw != want {
						t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v; want %q", code, got, length, ok, err, want)
					}
					count++
				}
			}
		}
	}
	if count != 8192 {
		t.Fatalf("covered %d VEX VPALIGNR register encodings, want 8192", count)
	}
}

func TestDecodedX86RawVPALIGNRCompleteEVEXRegisterFamily(t *testing.T) {
	count := 0
	for vectorBits, vectorName := range []string{"X", "Y", "Z"} {
		for _, masking := range []struct {
			mask    int
			zeroing bool
			suffix  string
		}{
			{},
			{mask: 3},
			{mask: 7, zeroing: true, suffix: ".Z"},
		} {
			for first := 0; first < 32; first++ {
				for second := 0; second < 32; second++ {
					for destination := 0; destination < 32; destination++ {
						immediate := byte(first*8 + destination)
						code := encodeX86RawEVEXVPALIGNR(immediate, byte(vectorBits), masking.mask, masking.zeroing, first, second, destination)
						got, length, ok, err := decodedX86PackedAlignRightInstruction(code, 64)
						args := []string{
							fmt.Sprintf("$%d", immediate),
							fmt.Sprintf("%s%d", vectorName, first),
							fmt.Sprintf("%s%d", vectorName, second),
						}
						if masking.mask != 0 {
							args = append(args, fmt.Sprintf("K%d", masking.mask))
						}
						args = append(args, fmt.Sprintf("%s%d", vectorName, destination))
						want := "VPALIGNR" + masking.suffix + " " + strings.Join(args, ", ")
						if err != nil || !ok || length != len(code) || got.Raw != want {
							t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v; want %q", code, got, length, ok, err, want)
						}
						count++
					}
				}
			}
		}
	}
	if count != 294912 {
		t.Fatalf("covered %d EVEX VPALIGNR register encodings, want 294912", count)
	}
}

func TestDecodedX86RawPackedAlignRightMemoryAndInvalidForms(t *testing.T) {
	for _, test := range []struct {
		name string
		code []byte
		want string
	}{
		{
			name: "legacy extended SIB",
			code: []byte{0x64, 0x66, 0x47, 0x0f, 0x3a, 0x0f, 0x64, 0x8b, 0x20, 0xff},
			want: "PALIGNR $255, 32(R11)(R9*4)(FS), X12",
		},
		{
			name: "VEX extended SIB",
			code: []byte{0x65, 0xc4, 0x03, 0x15, 0x0f, 0x64, 0x8b, 0x20, 0xfe},
			want: "VPALIGNR $254, 32(R11)(R9*4)(GS), Y13, Y12",
		},
		{
			name: "EVEX compressed disp8 zero mask",
			code: []byte{0x64, 0x62, 0x03, 0x15, 0xc2, 0x0f, 0x64, 0x8b, 0x7f, 0xfd},
			want: "VPALIGNR.Z $253, 8128(R11)(R9*4)(FS), Z29, K2, Z28",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, length, ok, err := decodedX86PackedAlignRightInstruction(test.code, 64)
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
		{name: "VEX 386 operand limit", mode: 32, encoding: encodeX86RawVEXVPALIGNR(1, false, 0, 1, 2), wantOK: true},
		{name: "EVEX 386 operand limit", mode: 32, encoding: encodeX86RawEVEXVPALIGNR(1, 0, 0, false, 0, 1, 2), wantOK: true},
		{name: "VEX wrong pp", mode: 64, encoding: []byte{0xc4, 0xe3, 0x40, 0x0f, 0xc6, 4}, wantOK: true},
		{name: "VEX W", mode: 64, encoding: []byte{0xc4, 0xe3, 0xc1, 0x0f, 0xc6, 4}, wantOK: true},
		{name: "VEX truncated immediate", mode: 64, encoding: []byte{0xc4, 0xe3, 0x41, 0x0f, 0xc6}, wantOK: true},
		{name: "EVEX W", mode: 64, encoding: []byte{0x62, 0xf3, 0x85, 0x08, 0x0f, 0xc2, 4}, wantOK: true},
		{name: "EVEX broadcast", mode: 64, encoding: []byte{0x62, 0xf3, 0x05, 0x18, 0x0f, 0x02, 4}, wantOK: true},
		{name: "EVEX reserved vector length", mode: 64, encoding: []byte{0x62, 0xf3, 0x05, 0x68, 0x0f, 0xc2, 4}, wantOK: true},
		{name: "EVEX zero without mask", mode: 64, encoding: []byte{0x62, 0xf3, 0x05, 0x88, 0x0f, 0xc2, 4}, wantOK: true},
		{name: "EVEX truncated immediate", mode: 64, encoding: []byte{0x62, 0xf3, 0x05, 0x08, 0x0f, 0xc2}, wantOK: true},
		{name: "legacy REX.W", mode: 64, encoding: []byte{0x66, 0x48, 0x0f, 0x3a, 0x0f, 0xc2, 4}, wantOK: true},
		{name: "legacy RIP relative", mode: 64, encoding: []byte{0x66, 0x0f, 0x3a, 0x0f, 0x05, 0, 0, 0, 0, 4}, wantOK: true},
		{name: "address override", mode: 64, encoding: []byte{0x67, 0xc4, 0xe3, 0x41, 0x0f, 0xc6, 4}, wantOK: true},
		{name: "wrong opcode", mode: 64, encoding: []byte{0xc4, 0xe3, 0x41, 0x0e, 0xc6, 4}},
		{name: "wrong map", mode: 64, encoding: []byte{0xc4, 0xe2, 0x41, 0x0f, 0xc6, 4}},
		{name: "legacy missing 66", mode: 64, encoding: []byte{0x0f, 0x3a, 0x0f, 0xc2, 4}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, ok, err := decodedX86PackedAlignRightInstruction(test.encoding, test.mode)
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
