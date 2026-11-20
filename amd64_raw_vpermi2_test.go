package plan9asm

import (
	"strings"
	"testing"
)

func TestDecodedX86VPERMI2CompleteGo127Family(t *testing.T) {
	// Go 1.27 shares _yvblendmpd across VPERMI2B/W/D/Q/PS/PD. These
	// LLVM-verified bytes cover all six opcodes, X/Y/Z widths, high registers,
	// memory, masking, zeroing, broadcast, and compressed disp8 scaling.
	tests := []struct {
		name string
		code []byte
		want string
	}{
		{name: "b x high masked", code: []byte{0x62, 0xa2, 0x55, 0x01, 0x75, 0xf4}, want: "VPERMI2B X20, X21, K1, X22"},
		{name: "w y memory zeroing", code: []byte{0x62, 0xd2, 0xf5, 0xaa, 0x75, 0x50, 0x03}, want: "VPERMI2W.Z 96(R8), Y1, K2, Y2"},
		{name: "d z high", code: []byte{0x62, 0x32, 0x7d, 0x40, 0x76, 0xc9}, want: "VPERMI2D Z17, Z16, Z9"},
		{name: "d z broadcast zeroing", code: []byte{0x62, 0xf2, 0x75, 0xdb, 0x76, 0x50, 0x7f}, want: "VPERMI2D.BCST.Z 508(AX), Z1, K3, Z2"},
		{name: "q reported minio", code: []byte{0x62, 0x22, 0xb5, 0x48, 0x76, 0xf2}, want: "VPERMI2Q Z18, Z9, Z30"},
		{name: "q y high memory masked", code: []byte{0x62, 0x42, 0xbd, 0x24, 0x76, 0x4c, 0x24, 0x02}, want: "VPERMI2Q 64(R12), Y24, K4, Y25"},
		{name: "ps x high masked", code: []byte{0x62, 0xa2, 0x55, 0x01, 0x77, 0xf4}, want: "VPERMI2PS X20, X21, K1, X22"},
		{name: "pd z broadcast zeroing", code: []byte{0x62, 0xf2, 0xf5, 0xdb, 0x77, 0x50, 0x7f}, want: "VPERMI2PD.BCST.Z 1016(AX), Z1, K3, Z2"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			instruction, length, ok, err := decodedX86IndexedPermuteInstruction(test.code, 64)
			if !ok {
				t.Fatal("VPERMI2 encoding was not recognized")
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

func TestDecodeX86RawDirectiveGroupReportedMinioVPERMI2Q(t *testing.T) {
	code := []byte{0x62, 0x22, 0xb5, 0x48, 0x76, 0xf2}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "minio VPERMI2Q", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || decoded[0].Op != "VPERMI2Q" || !strings.HasPrefix(decoded[0].Raw, "VPERMI2Q Z18, Z9, Z30 ") {
		t.Fatalf("decoded reported minio bytes as %#v", decoded)
	}
}
