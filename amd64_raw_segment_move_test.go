package plan9asm

import (
	"fmt"
	"testing"
)

func TestDecodedX86RawSegmentMoveCompleteRegisterFamily(t *testing.T) {
	segments := []string{"ES", "CS", "SS", "DS", "FS", "GS"}
	count := 0
	for _, mode := range []int{32, 64} {
		registers := 8
		if mode == 64 {
			registers = 16
		}
		for segmentNumber, segment := range segments {
			for general := 0; general < registers; general++ {
				rex := byte(0)
				if mode == 64 && general >= 8 {
					rex = 0x41
				}
				for _, direction := range []struct {
					opcode byte
					want   string
				}{
					{opcode: 0x8e, want: fmt.Sprintf("MOVW %s, %s", decodedX86RegisterNameForTest(general), segment)},
					{opcode: 0x8c, want: fmt.Sprintf("MOVW %s, %s", segment, decodedX86RegisterNameForTest(general))},
				} {
					code := make([]byte, 0, 3)
					if rex != 0 {
						code = append(code, rex)
					}
					code = append(code, direction.opcode, byte(0xc0|segmentNumber<<3|general&7))
					got, length, ok, err := decodedX86SegmentMoveInstruction(code, mode)
					if err != nil || !ok || length != len(code) || got.Raw != direction.want {
						t.Fatalf("decode mode=%d %x = %+v, length=%d, ok=%v, err=%v; want %q", mode, code, got, length, ok, err, direction.want)
					}
					count++
				}
			}
		}
	}
	if count != 288 {
		t.Fatalf("covered %d raw segment-register moves, want 288", count)
	}
}

func decodedX86RegisterNameForTest(number int) string {
	reg, ok := decodedX86GeneralRegister(number)
	if !ok {
		panic(number)
	}
	return string(reg)
}

func TestDecodedX86RawSegmentMoveMemoryAndInvalidForms(t *testing.T) {
	for _, test := range []struct {
		name string
		mode int
		code []byte
		want string
	}{
		{
			name: "load FS from extended SIB with FS override",
			mode: 64,
			code: []byte{0x64, 0x43, 0x8e, 0x64, 0x8b, 0x20},
			want: "MOVW 32(R11)(R9*4)(FS), FS",
		},
		{
			name: "store GS to extended SIB with GS override",
			mode: 64,
			code: []byte{0x65, 0x43, 0x8c, 0x6c, 0x8b, 0x20},
			want: "MOVW GS, 32(R11)(R9*4)(GS)",
		},
		{
			name: "386 absolute memory",
			mode: 32,
			code: []byte{0x66, 0x8e, 0x1d, 0x78, 0x56, 0x34, 0x12},
			want: "MOVW 305419896(), DS",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, length, ok, err := decodedX86SegmentMoveInstruction(test.code, test.mode)
			if err != nil || !ok || length != len(test.code) || got.Raw != test.want {
				t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v; want %q", test.code, got, length, ok, err, test.want)
			}
		})
	}

	for _, test := range []struct {
		name     string
		encoding []byte
		wantOK   bool
	}{
		{name: "reserved segment six", encoding: []byte{0x8e, 0xf0}, wantOK: true},
		{name: "reserved segment seven", encoding: []byte{0x8c, 0xf8}, wantOK: true},
		{name: "REX.R reserved segment", encoding: []byte{0x44, 0x8e, 0xc0}, wantOK: true},
		{name: "RIP relative", encoding: []byte{0x8e, 0x1d, 0, 0, 0, 0}, wantOK: true},
		{name: "address override", encoding: []byte{0x67, 0x8e, 0xd8}, wantOK: true},
		{name: "truncated", encoding: []byte{0x8e}, wantOK: false},
		{name: "unrelated opcode", encoding: []byte{0x8f, 0xd8}, wantOK: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, ok, err := decodedX86SegmentMoveInstruction(test.encoding, 64)
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
