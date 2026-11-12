package plan9asm

import (
	"strings"
	"testing"
)

func TestDecodedX86Shuffle128BitBlocksCompleteGo127Family(t *testing.T) {
	// Go 1.27 shares _yvshuff32x4 across these four instructions. Its
	// EVEX-only rows cover Y/Z register or memory sources, high registers,
	// K masking, zeroing, scalar broadcast, and compressed disp8 scaling.
	tests := []struct {
		name string
		code []byte
		want string
	}{
		{name: "f32 y high masked", code: []byte{0x62, 0xa3, 0x55, 0x21, 0x23, 0xf4, 0x06}, want: "VSHUFF32X4 $6, Y20, Y21, K1, Y22"},
		{name: "f32 z memory zeroing", code: []byte{0x62, 0xd3, 0x75, 0xca, 0x23, 0x50, 0x03, 0x07}, want: "VSHUFF32X4.Z $7, 192(R8), Z1, K2, Z2"},
		{name: "f64 reported minio", code: []byte{0x62, 0x23, 0x8d, 0x40, 0x23, 0xc0, 0xee}, want: "VSHUFF64X2 $238, Z16, Z30, Z24"},
		{name: "f64 z broadcast zeroing", code: []byte{0x62, 0xf3, 0xf5, 0xdb, 0x23, 0x50, 0x7f, 0x09}, want: "VSHUFF64X2.BCST.Z $9, 1016(AX), Z1, K3, Z2"},
		{name: "i32 y high memory masked", code: []byte{0x62, 0x43, 0x3d, 0x24, 0x43, 0x4c, 0x24, 0x02, 0x0a}, want: "VSHUFI32X4 $10, 64(R12), Y24, K4, Y25"},
		{name: "i32 z high", code: []byte{0x62, 0x33, 0x7d, 0x40, 0x43, 0xc9, 0x44}, want: "VSHUFI32X4 $68, Z17, Z16, Z9"},
		{name: "i64 y high masked", code: []byte{0x62, 0xa3, 0xd5, 0x21, 0x43, 0xf4, 0x06}, want: "VSHUFI64X2 $6, Y20, Y21, K1, Y22"},
		{name: "i64 z broadcast zeroing", code: []byte{0x62, 0xf3, 0xf5, 0xdb, 0x43, 0x50, 0x7f, 0x09}, want: "VSHUFI64X2.BCST.Z $9, 1016(AX), Z1, K3, Z2"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			instruction, length, ok, err := decodedX86Shuffle128BitBlocksInstruction(test.code, 64)
			if !ok {
				t.Fatal("shuffle-block encoding was not recognized")
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

func TestDecodeX86RawDirectiveGroupReportedMinioVSHUFF64X2(t *testing.T) {
	code := []byte{0x62, 0x23, 0x8d, 0x40, 0x23, 0xc0, 0xee}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "minio VSHUFF64X2", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || decoded[0].Op != "VSHUFF64X2" || !strings.HasPrefix(decoded[0].Raw, "VSHUFF64X2 $238, Z16, Z30, Z24 ") {
		t.Fatalf("decoded reported minio bytes as %#v", decoded)
	}
}
