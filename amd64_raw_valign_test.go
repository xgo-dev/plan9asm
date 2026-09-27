package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestDecodeX86RawVectorAlignCompleteGo127Family(t *testing.T) {
	tests := []struct {
		name string
		code []byte
		want string
	}{
		{name: "dword x high masked", code: []byte{0x62, 0xa3, 0x55, 0x01, 0x03, 0xf4, 0xca}, want: "VALIGND $202, X20, X21, K1, X22"},
		{name: "qword y memory zeroing", code: []byte{0x62, 0xd3, 0xf5, 0xaa, 0x03, 0x50, 0x03, 0x96}, want: "VALIGNQ.Z $150, 96(R8), Y1, K2, Y2"},
		{name: "dword z register", code: []byte{0x62, 0x73, 0x55, 0x48, 0x03, 0xce, 0xca}, want: "VALIGND $202, Z6, Z5, Z9"},
		{name: "dword z broadcast high masked", code: []byte{0x62, 0x53, 0x7d, 0x54, 0x03, 0x4c, 0x24, 0x7f, 0x44}, want: "VALIGND.BCST $68, 508(R12), Z16, K4, Z9"},
		{name: "qword z broadcast zeroing", code: []byte{0x62, 0xf3, 0xf5, 0xdb, 0x03, 0x50, 0x7f, 0x09}, want: "VALIGNQ.BCST.Z $9, 1016(AX), Z1, K3, Z2"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decoded, err := decodeX86RawDirectiveGroup(test.code, 64, 0, "VALIGN", map[string]bool{})
			if err != nil {
				t.Fatal(err)
			}
			if len(decoded) != 1 || !strings.HasPrefix(decoded[0].Raw, test.want+" ") {
				t.Fatalf("decoded %x as %#v, want %q", test.code, decoded, test.want)
			}
		})
	}
}

func TestDecodedX86RawVectorAlignAllRegisterFields(t *testing.T) {
	for _, lane := range []struct {
		w  byte
		op Op
	}{
		{w: 0, op: "VALIGND"},
		{w: 1, op: "VALIGNQ"},
	} {
		for vectorBits, vectorName := range []string{"X", "Y", "Z"} {
			for first := 0; first < 32; first++ {
				for second := 0; second < 32; second++ {
					for destination := 0; destination < 32; destination++ {
						p0 := byte((^destination>>3)&1)<<7 |
							byte((^first>>4)&1)<<6 |
							byte((^first>>3)&1)<<5 |
							byte((^destination>>4)&1)<<4 | 3
						p1 := lane.w<<7 | byte(^second&15)<<3 | 5
						p2 := byte(vectorBits)<<5 | byte((^second>>4)&1)<<3
						modRM := byte(0xc0 | destination&7<<3 | first&7)
						encoding := []byte{0x62, p0, p1, p2, 0x03, modRM, 0xa5}
						instruction, length, ok, err := decodedX86VectorAlignInstruction(encoding, 64)
						if !ok || err != nil || length != len(encoding) {
							t.Fatalf("op=%s width=%s first=%d second=%d destination=%d: ok=%v length=%d err=%v", lane.op, vectorName, first, second, destination, ok, length, err)
						}
						want := fmt.Sprintf("%s $165, %s%d, %s%d, %s%d", lane.op, vectorName, first, vectorName, second, vectorName, destination)
						if instruction.Raw != want {
							t.Fatalf("encoding %x decoded as %q, want %q", encoding, instruction.Raw, want)
						}
					}
				}
			}
		}
	}
}

func TestDecodedX86RawVectorAlignRejectsReservedAndUnsafeForms(t *testing.T) {
	for _, test := range []struct {
		name     string
		mode     int
		encoding []byte
		wantOK   bool
	}{
		{name: "386 operand limit", mode: 32, encoding: []byte{0x62, 0xf3, 0x75, 0x08, 0x03, 0xc2, 0x01}, wantOK: true},
		{name: "reserved vector length", mode: 64, encoding: []byte{0x62, 0xf3, 0x75, 0x68, 0x03, 0xc2, 0x01}, wantOK: true},
		{name: "broadcast register", mode: 64, encoding: []byte{0x62, 0xf3, 0x75, 0x18, 0x03, 0xc2, 0x01}, wantOK: true},
		{name: "zero without mask", mode: 64, encoding: []byte{0x62, 0xf3, 0x75, 0x88, 0x03, 0xc2, 0x01}, wantOK: true},
		{name: "address override", mode: 64, encoding: []byte{0x67, 0x62, 0xf3, 0x75, 0x08, 0x03, 0xc2, 0x01}, wantOK: true},
		{name: "missing immediate", mode: 64, encoding: []byte{0x62, 0xf3, 0x75, 0x08, 0x03, 0xc2}, wantOK: false},
		{name: "wrong map", mode: 64, encoding: []byte{0x62, 0xf2, 0x75, 0x08, 0x03, 0xc2, 0x01}, wantOK: false},
		{name: "wrong prefix", mode: 64, encoding: []byte{0x62, 0xf3, 0x74, 0x08, 0x03, 0xc2, 0x01}, wantOK: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, ok, err := decodedX86VectorAlignInstruction(test.encoding, test.mode)
			if ok != test.wantOK {
				t.Fatalf("encoding %x: ok=%v, want %v (err=%v)", test.encoding, ok, test.wantOK, err)
			}
			if test.wantOK && err == nil {
				t.Fatalf("encoding %x was recognized without rejection", test.encoding)
			}
		})
	}
}
