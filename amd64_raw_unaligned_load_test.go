package plan9asm

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
)

func TestDecodedX86VEXUnalignedLoadCompleteMemoryForms(t *testing.T) {
	for _, mode := range []int{32, 64} {
		limit := 8
		if mode == 64 {
			limit = 16
		}
		for _, memory := range []struct {
			encoded []byte
			source  string
		}{
			{[]byte{0x00}, "(AX)"},
			{[]byte{0x40, 0x81}, "-127(AX)"},
			{[]byte{0x80, 0x78, 0x56, 0x34, 0x12}, "305419896(AX)"},
			{[]byte{0x44, 0x8b, 0x10}, "16(BX)(CX*4)"},
		} {
			for _, segment := range []struct {
				prefix []byte
				name   Reg
			}{{nil, ""}, {[]byte{0x64}, FS}, {[]byte{0x65}, GS}} {
				for width, bank := range []string{"X", "Y"} {
					for destination := 0; destination < limit; destination++ {
						for _, header := range [][]byte{
							{0xc5, byte(0xfb ^ destination/8<<7 | width<<2), 0xf0},
							{0xc4, byte(0xe1 ^ destination/8<<7), byte(0x7b | width<<2), 0xf0},
							{0xc4, byte(0xe1 ^ destination/8<<7), byte(0xfb | width<<2), 0xf0},
						} {
							code := append(append([]byte(nil), segment.prefix...), header...)
							address := append([]byte(nil), memory.encoded...)
							address[0] |= byte(destination&7) << 3
							code = append(code, address...)
							want := x86ScalarLaneInstruction(t, fmt.Sprintf("VLDDQU %s,%s%d", memory.source, bank, destination))
							want.Args[0].Mem.Segment = segment.name
							got, length, known, err := decodedX86VEXUnalignedLoadInstruction(append(code, 0xcc), mode)
							if err != nil || !known || length != len(code) || got.Op != want.Op ||
								!reflect.DeepEqual(got.Args, want.Args) || !got.x86Encoded {
								t.Fatalf("complete VLDDQU %x mode%d: got=%+v length=%d known=%v err=%v want=%+v", code, mode, got, length, known, err, want)
							}
						}
					}
				}
			}
		}
	}
}

func TestDecodedX86VEXUnalignedLoadInvalidAndWholeBoundaries(t *testing.T) {
	for _, mode := range []int{32, 64} {
		for _, test := range []struct {
			name string
			code []byte
		}{
			{"reserved-vvvv", []byte{0xc4, 0xe1, 0x73, 0xf0, 0x00}},
			{"register-source", []byte{0xc4, 0xe1, 0x7b, 0xf0, 0xc0}},
			{"missing-modrm", []byte{0xc4, 0xe1, 0x7b, 0xf0}},
			{"missing-sib", []byte{0xc4, 0xe1, 0x7b, 0xf0, 0x04}},
			{"missing-disp8", []byte{0xc4, 0xe1, 0x7b, 0xf0, 0x40}},
			{"short-disp32", []byte{0xc4, 0xe1, 0x7b, 0xf0, 0x80, 0, 0, 0}},
			{"no-evex-form", []byte{0x62, 0xf1, 0x7f, 0x08, 0xf0, 0x00}},
			{"address-layout", []byte{0x67, 0xc4, 0xe1, 0x7b, 0xf0, 0x00}},
		} {
			t.Run(fmt.Sprintf("mode%d/%s", mode, test.name), func(t *testing.T) {
				_, _, known, err := decodedX86VEXUnalignedLoadInstruction(test.code, mode)
				if !known || err == nil {
					t.Fatal("invalid or incomplete physical VLDDQU accepted", known, err)
				}
			})
		}
		t.Run(fmt.Sprintf("mode%d/maximum-instruction-length", mode), func(t *testing.T) {
			base := []byte{0xc4, 0xe1, 0x7b, 0xf0, 0x40, 1}
			valid := append(bytes.Repeat([]byte{0x64}, 9), base...)
			if _, length, known, err := decodedX86VEXUnalignedLoadInstruction(valid, mode); !known || err != nil || length != 15 {
				t.Fatal("complete legal 15-byte boundary lost", length, known, err)
			}
			invalid := append(bytes.Repeat([]byte{0x64}, 10), base...)
			if _, _, known, err := decodedX86VEXUnalignedLoadInstruction(invalid, mode); !known || err == nil {
				t.Fatal("machine-invalid instruction longer than 15 bytes accepted", known, err)
			}
		})
	}
}
