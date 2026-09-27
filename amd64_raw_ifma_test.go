package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestDecodeX86RawDirectiveGroupIFMACompleteFamily(t *testing.T) {
	// Bytes come from Go 1.27's avx512_ifma assembler test table and cover
	// both opcodes, all widths, high registers, memory, and masking.
	for _, test := range []struct {
		name string
		code []byte
		want string
	}{
		{name: "high x high registers", code: []byte{0x62, 0xe2, 0xa5, 0x09, 0xb5, 0xd7}, want: "VPMADD52HUQ X7, X11, K1, X18"},
		{name: "high y high registers", code: []byte{0x62, 0x82, 0x85, 0x27, 0xb5, 0xcc}, want: "VPMADD52HUQ Y28, Y31, K7, Y17"},
		{name: "low y memory", code: []byte{0x62, 0xf2, 0xb5, 0x29, 0xb4, 0x94, 0x2c, 0x11, 0, 0, 0}, want: "VPMADD52LUQ 17(SP)(BP*1), Y9, K1, Y2"},
		{name: "low z high registers", code: []byte{0x62, 0x22, 0xd5, 0x47, 0xb4, 0xe0}, want: "VPMADD52LUQ Z16, Z21, K7, Z28"},
		{name: "low z broadcast zeroing", code: []byte{0x62, 0xf2, 0xf5, 0xdb, 0xb4, 0x50, 0x7f}, want: "VPMADD52LUQ.BCST.Z 1016(AX), Z1, K3, Z2"},
	} {
		t.Run(test.name, func(t *testing.T) {
			decoded, err := decodeX86RawDirectiveGroup(test.code, 64, 0, test.name, map[string]bool{})
			if err != nil {
				t.Fatal(err)
			}
			if len(decoded) != 1 || !strings.HasPrefix(decoded[0].Raw, test.want+" ") {
				t.Fatalf("decoded %x as %#v, want %q", test.code, decoded, test.want)
			}
		})
	}
}

func TestDecodedX86RawIFMAAllRegisterFields(t *testing.T) {
	for _, operation := range []struct {
		opcode byte
		op     Op
	}{
		{opcode: 0xb4, op: "VPMADD52LUQ"},
		{opcode: 0xb5, op: "VPMADD52HUQ"},
	} {
		for vectorBits, vectorName := range []string{"X", "Y", "Z"} {
			for first := 0; first < 32; first++ {
				for second := 0; second < 32; second++ {
					for destination := 0; destination < 32; destination++ {
						p0 := byte((^destination>>3)&1)<<7 |
							byte((^first>>4)&1)<<6 |
							byte((^first>>3)&1)<<5 |
							byte((^destination>>4)&1)<<4 | 2
						p1 := byte(1)<<7 | byte(^second&15)<<3 | 5
						p2 := byte(vectorBits)<<5 | byte((^second>>4)&1)<<3
						modRM := byte(0xc0 | destination&7<<3 | first&7)
						encoding := []byte{0x62, p0, p1, p2, operation.opcode, modRM}
						instruction, length, ok, err := decodedX86IFMAInstruction(encoding, 64)
						if !ok || err != nil || length != len(encoding) {
							t.Fatalf("op=%s width=%s first=%d second=%d destination=%d: ok=%v length=%d err=%v", operation.op, vectorName, first, second, destination, ok, length, err)
						}
						want := fmt.Sprintf("%s %s%d, %s%d, %s%d", operation.op, vectorName, first, vectorName, second, vectorName, destination)
						if instruction.Raw != want {
							t.Fatalf("encoding %x decoded as %q, want %q", encoding, instruction.Raw, want)
						}
					}
				}
			}
		}
	}
}

func TestDecodedX86RawIFMARejectsReservedAndUnsafeForms(t *testing.T) {
	for _, test := range []struct {
		name     string
		mode     int
		encoding []byte
		wantOK   bool
	}{
		{name: "386 masked operand limit", mode: 32, encoding: []byte{0x62, 0xf2, 0xf5, 0x09, 0xb4, 0xc2}, wantOK: true},
		{name: "386 extended register", mode: 32, encoding: []byte{0x62, 0x72, 0xf5, 0x08, 0xb4, 0xc2}, wantOK: true},
		{name: "reserved vector length", mode: 64, encoding: []byte{0x62, 0xf2, 0xf5, 0x68, 0xb4, 0xc2}, wantOK: true},
		{name: "broadcast register", mode: 64, encoding: []byte{0x62, 0xf2, 0xf5, 0x18, 0xb4, 0xc2}, wantOK: true},
		{name: "zero without mask", mode: 64, encoding: []byte{0x62, 0xf2, 0xf5, 0x88, 0xb5, 0xc2}, wantOK: true},
		{name: "address override", mode: 64, encoding: []byte{0x67, 0x62, 0xf2, 0xf5, 0x08, 0xb4, 0xc2}, wantOK: true},
		{name: "wrong map", mode: 64, encoding: []byte{0x62, 0xf3, 0xf5, 0x08, 0xb4, 0xc2}, wantOK: false},
		{name: "wrong prefix", mode: 64, encoding: []byte{0x62, 0xf2, 0xf4, 0x08, 0xb4, 0xc2}, wantOK: false},
		{name: "wrong w", mode: 64, encoding: []byte{0x62, 0xf2, 0x75, 0x08, 0xb4, 0xc2}, wantOK: true},
		{name: "truncated", mode: 64, encoding: []byte{0x62, 0xf2, 0xf5, 0x08, 0xb4}, wantOK: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, ok, err := decodedX86IFMAInstruction(test.encoding, test.mode)
			if ok != test.wantOK {
				t.Fatalf("encoding %x: ok=%v, want %v (err=%v)", test.encoding, ok, test.wantOK, err)
			}
			if test.wantOK && err == nil {
				t.Fatalf("encoding %x was recognized without rejection", test.encoding)
			}
		})
	}
}
