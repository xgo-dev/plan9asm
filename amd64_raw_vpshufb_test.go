package plan9asm

import (
	"strings"
	"testing"
)

func TestDecodedX86VPSHUFBCompleteGo127Family(t *testing.T) {
	// Go 1.27's _yvandnpd table gives VPSHUFB VEX X/Y forms and EVEX
	// X/Y/Z forms, including high registers, memory, K masking, zeroing,
	// and EVEX compressed disp8 scaling. LLVM 22 verified these bytes.
	tests := []struct {
		name string
		code []byte
		want string
	}{
		{name: "vex x high destination", code: []byte{0xc4, 0x62, 0x79, 0x00, 0xc1}, want: "VPSHUFB X1, X0, X8"},
		{name: "vex y high memory", code: []byte{0xc4, 0x42, 0x6d, 0x00, 0x4c, 0x24, 0x20}, want: "VPSHUFB 32(R12), Y2, Y9"},
		{name: "evex x high masked", code: []byte{0x62, 0xa2, 0x55, 0x01, 0x00, 0xf4}, want: "VPSHUFB X20, X21, K1, X22"},
		{name: "evex y memory zeroing", code: []byte{0x62, 0xd2, 0x75, 0xaa, 0x00, 0x50, 0x03}, want: "VPSHUFB.Z 96(R8), Y1, K2, Y2"},
		{name: "evex z high", code: []byte{0x62, 0x32, 0x7d, 0x40, 0x00, 0xc9}, want: "VPSHUFB Z17, Z16, Z9"},
		{name: "evex z compressed memory zeroing", code: []byte{0x62, 0xf2, 0x75, 0xcb, 0x00, 0x50, 0x7f}, want: "VPSHUFB.Z 8128(AX), Z1, K3, Z2"},
		{name: "reported minio", code: []byte{0x62, 0xc2, 0x7d, 0x40, 0x00, 0xc3}, want: "VPSHUFB Z11, Z16, Z16"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			instruction, length, ok, err := decodedX86VPSHUFBInstruction(test.code, 64)
			if !ok {
				t.Fatal("VPSHUFB encoding was not recognized")
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

func TestDecodeX86RawDirectiveGroupReportedMinioVPSHUFB(t *testing.T) {
	code := []byte{0x62, 0xc2, 0x7d, 0x40, 0x00, 0xc3}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "minio VPSHUFB", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || decoded[0].Op != "VPSHUFB" || !strings.HasPrefix(decoded[0].Raw, "VPSHUFB Z11, Z16, Z16 ") {
		t.Fatalf("decoded reported minio bytes as %#v", decoded)
	}
}
