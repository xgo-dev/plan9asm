package plan9asm

import (
	"strings"
	"testing"
)

func TestDecodedX86PackedImmediateRotateCompleteGo127Family(t *testing.T) {
	// Go 1.27's _yvprold table covers the four EVEX immediate rotate
	// instructions across X/Y/Z, memory, masks, zeroing, broadcast, high
	// registers, and compressed disp8. LLVM 22 verified these bytes.
	tests := []struct {
		name string
		code []byte
		want string
	}{
		{name: "left dword x high masked", code: []byte{0x62, 0xb1, 0x4d, 0x01, 0x72, 0xcc, 0x06}, want: "VPROLD $6, X20, K1, X22"},
		{name: "left qword y memory zeroing", code: []byte{0x62, 0xd1, 0xed, 0xaa, 0x72, 0x48, 0x03, 0x07}, want: "VPROLQ.Z $7, 96(R8), K2, Y2"},
		{name: "right dword reported minio", code: []byte{0x62, 0xf1, 0x2d, 0x48, 0x72, 0xc4, 0x06}, want: "VPRORD $6, Z4, Z10"},
		{name: "right dword z broadcast high masked", code: []byte{0x62, 0xd1, 0x35, 0x5c, 0x72, 0x44, 0x24, 0x7f, 0x44}, want: "VPRORD.BCST $68, 508(R12), K4, Z9"},
		{name: "right qword z broadcast zeroing", code: []byte{0x62, 0xf1, 0xed, 0xdb, 0x72, 0x40, 0x7f, 0x09}, want: "VPRORQ.BCST.Z $9, 1016(AX), K3, Z2"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			instruction, length, ok, err := decodedX86PackedImmediateRotateInstruction(test.code, 64)
			if !ok {
				t.Fatal("packed immediate rotate encoding was not recognized")
			}
			if err != nil {
				t.Fatal(err)
			}
			if length != len(test.code) || instruction.Raw != test.want {
				t.Fatalf("decoded %x as length=%d raw=%q, want length=%d raw=%q", test.code, length, instruction.Raw, len(test.code), test.want)
			}
		})
	}
}

func TestDecodeX86RawDirectiveGroupReportedMinioVPRORD(t *testing.T) {
	code := []byte{0x62, 0xf1, 0x2d, 0x48, 0x72, 0xc4, 0x06}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "minio VPRORD", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || decoded[0].Op != "VPRORD" || !strings.HasPrefix(decoded[0].Raw, "VPRORD $6, Z4, Z10 ") {
		t.Fatalf("decoded reported minio bytes as %#v", decoded)
	}
}
