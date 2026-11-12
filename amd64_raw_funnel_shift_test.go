package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestDecodeX86RawDirectiveGroupFunnelShiftCompleteFamily(t *testing.T) {
	// Bytes are Go 1.27 assembler oracle cases spanning immediate/variable,
	// left/right, W/D/Q, and high EVEX registers.
	for _, test := range []struct {
		name string
		code []byte
		want string
	}{
		{name: "left immediate w", code: []byte{0x62, 0x13, 0xc5, 0x0b, 0x70, 0xd8, 0x41}, want: "VPSHLDW $65, X24, X7, K3, X11"},
		{name: "left immediate d", code: []byte{0x62, 0x43, 0x05, 0x04, 0x71, 0xd0, 0x2f}, want: "VPSHLDD $47, X8, X31, K4, X26"},
		{name: "left immediate q", code: []byte{0x62, 0x33, 0xd5, 0x04, 0x71, 0xfe, 0x5e}, want: "VPSHLDQ $94, X22, X21, K4, X15"},
		{name: "right immediate w", code: []byte{0x62, 0xc3, 0xfd, 0x09, 0x72, 0xf7, 0x1b}, want: "VPSHRDW $27, X15, X0, K1, X22"},
		{name: "right immediate q", code: []byte{0x62, 0x53, 0xfd, 0x03, 0x73, 0xee, 0x2a}, want: "VPSHRDQ $42, X14, X16, K3, X13"},
		{name: "left variable w", code: []byte{0x62, 0x32, 0xb5, 0x0f, 0x70, 0xea}, want: "VPSHLDVW X18, X9, K7, X13"},
		{name: "left variable d", code: []byte{0x62, 0xd2, 0x75, 0x0f, 0x71, 0xff}, want: "VPSHLDVD X15, X1, K7, X7"},
		{name: "left variable q", code: []byte{0x62, 0x72, 0xf5, 0x07, 0x71, 0xe3}, want: "VPSHLDVQ X3, X17, K7, X12"},
		{name: "right variable w", code: []byte{0x62, 0xf2, 0xed, 0x0f, 0x72, 0xc2}, want: "VPSHRDVW X2, X2, K7, X0"},
		{name: "right variable d", code: []byte{0x62, 0x32, 0x1d, 0x0a, 0x73, 0xc7}, want: "VPSHRDVD X23, X12, K2, X8"},
		{name: "right variable q", code: []byte{0x62, 0x22, 0xa5, 0x09, 0x73, 0xc4}, want: "VPSHRDVQ X20, X11, K1, X24"},
		{name: "left variable d broadcast zero", code: []byte{0x62, 0xf2, 0x75, 0xdb, 0x71, 0x50, 0x7f}, want: "VPSHLDVD.BCST.Z 508(AX), Z1, K3, Z2"},
		{name: "right immediate q broadcast zero", code: []byte{0x62, 0xf3, 0xf5, 0xdb, 0x73, 0x50, 0x7f, 0x09}, want: "VPSHRDQ.BCST.Z $9, 1016(AX), Z1, K3, Z2"},
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

func TestDecodedX86RawFunnelShiftAllRegisterFields(t *testing.T) {
	for _, operation := range []struct {
		op       Op
		opcode   byte
		mapValue byte
		w        byte
		variable bool
	}{
		{op: "VPSHLDW", opcode: 0x70, mapValue: 3, w: 1},
		{op: "VPSHLDD", opcode: 0x71, mapValue: 3},
		{op: "VPSHLDQ", opcode: 0x71, mapValue: 3, w: 1},
		{op: "VPSHRDW", opcode: 0x72, mapValue: 3, w: 1},
		{op: "VPSHRDD", opcode: 0x73, mapValue: 3},
		{op: "VPSHRDQ", opcode: 0x73, mapValue: 3, w: 1},
		{op: "VPSHLDVW", opcode: 0x70, mapValue: 2, w: 1, variable: true},
		{op: "VPSHLDVD", opcode: 0x71, mapValue: 2, variable: true},
		{op: "VPSHLDVQ", opcode: 0x71, mapValue: 2, w: 1, variable: true},
		{op: "VPSHRDVW", opcode: 0x72, mapValue: 2, w: 1, variable: true},
		{op: "VPSHRDVD", opcode: 0x73, mapValue: 2, variable: true},
		{op: "VPSHRDVQ", opcode: 0x73, mapValue: 2, w: 1, variable: true},
	} {
		for vectorBits, vectorName := range []string{"X", "Y", "Z"} {
			for first := 0; first < 32; first++ {
				for second := 0; second < 32; second++ {
					for destination := 0; destination < 32; destination++ {
						p0 := byte((^destination>>3)&1)<<7 |
							byte((^first>>4)&1)<<6 |
							byte((^first>>3)&1)<<5 |
							byte((^destination>>4)&1)<<4 | operation.mapValue
						p1 := operation.w<<7 | byte(^second&15)<<3 | 5
						p2 := byte(vectorBits)<<5 | byte((^second>>4)&1)<<3
						modRM := byte(0xc0 | destination&7<<3 | first&7)
						encoding := []byte{0x62, p0, p1, p2, operation.opcode, modRM}
						if !operation.variable {
							encoding = append(encoding, 0xa5)
						}
						instruction, length, ok, err := decodedX86FunnelShiftInstruction(encoding, 64)
						if !ok || err != nil || length != len(encoding) {
							t.Fatalf("op=%s width=%s first=%d second=%d destination=%d: ok=%v length=%d err=%v", operation.op, vectorName, first, second, destination, ok, length, err)
						}
						immediate := ""
						if !operation.variable {
							immediate = "$165, "
						}
						want := fmt.Sprintf("%s %s%s%d, %s%d, %s%d", operation.op, immediate, vectorName, first, vectorName, second, vectorName, destination)
						if instruction.Raw != want {
							t.Fatalf("encoding %x decoded as %q, want %q", encoding, instruction.Raw, want)
						}
					}
				}
			}
		}
	}
}

func TestDecodedX86RawFunnelShiftRejectsReservedAndUnsafeForms(t *testing.T) {
	for _, test := range []struct {
		name     string
		mode     int
		encoding []byte
		wantOK   bool
	}{
		{name: "386 immediate operand limit", mode: 32, encoding: []byte{0x62, 0xf3, 0xf5, 0x08, 0x73, 0xc2, 1}, wantOK: true},
		{name: "386 variable masked operand limit", mode: 32, encoding: []byte{0x62, 0xf2, 0xf5, 0x09, 0x73, 0xc2}, wantOK: true},
		{name: "386 variable extended register", mode: 32, encoding: []byte{0x62, 0x72, 0xf5, 0x08, 0x73, 0xc2}, wantOK: true},
		{name: "reserved vector length", mode: 64, encoding: []byte{0x62, 0xf2, 0xf5, 0x68, 0x73, 0xc2}, wantOK: true},
		{name: "word broadcast", mode: 64, encoding: []byte{0x62, 0xf2, 0xf5, 0x18, 0x72, 0x10}, wantOK: true},
		{name: "broadcast register", mode: 64, encoding: []byte{0x62, 0xf2, 0xf5, 0x18, 0x73, 0xc2}, wantOK: true},
		{name: "zero without mask", mode: 64, encoding: []byte{0x62, 0xf2, 0xf5, 0x88, 0x73, 0xc2}, wantOK: true},
		{name: "address override", mode: 64, encoding: []byte{0x67, 0x62, 0xf2, 0xf5, 0x08, 0x73, 0xc2}, wantOK: true},
		{name: "wrong map", mode: 64, encoding: []byte{0x62, 0xf1, 0xf5, 0x08, 0x73, 0xc2}, wantOK: false},
		{name: "wrong prefix", mode: 64, encoding: []byte{0x62, 0xf2, 0xf4, 0x08, 0x73, 0xc2}, wantOK: false},
		{name: "word wrong w", mode: 64, encoding: []byte{0x62, 0xf2, 0x75, 0x08, 0x72, 0xc2}, wantOK: true},
		{name: "truncated immediate", mode: 64, encoding: []byte{0x62, 0xf3, 0xf5, 0x08, 0x73, 0xc2}, wantOK: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, ok, err := decodedX86FunnelShiftInstruction(test.encoding, test.mode)
			if ok != test.wantOK {
				t.Fatalf("encoding %x: ok=%v, want %v (err=%v)", test.encoding, ok, test.wantOK, err)
			}
			if test.wantOK && err == nil {
				t.Fatalf("encoding %x was recognized without rejection", test.encoding)
			}
		})
	}
}
