package plan9asm

import (
	"strings"
	"testing"
)

func TestX86RawImmediateThreeVectorSourceLocalRIPData(t *testing.T) {
	for _, family := range []struct {
		opcode byte
		name   string
	}{{0x25, "VPTERNLOG"}, {0x03, "VALIGN"}} {
		for _, qword := range []bool{false, true} {
			for vectorLength := 0; vectorLength < 3; vectorLength++ {
				for _, broadcast := range []bool{false, true} {
					p1 := byte(0x7d)
					laneWidth := 4
					suffix := "D"
					if qword {
						p1 |= 0x80
						laneWidth = 8
						suffix = "Q"
					}
					p2 := byte(0x08 | vectorLength<<5)
					width := 16 << vectorLength
					if broadcast {
						p2 |= 0x10
						width = laneWidth
					}
					code := []byte{0x62, 0xf3, p1, p2, family.opcode, 0x05, 1, 0, 0, 0, 0xca, 0xc3}
					for value := 0; value < width; value++ {
						code = append(code, byte(value))
					}
					decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "immediate three-vector RIP", map[string]bool{})
					if err != nil {
						t.Fatalf("%s%s width %d broadcast=%t: %v", family.name, suffix, width, broadcast, err)
					}
					if len(decoded) != 2 || len(decoded[0].x86RIPLiteralData) != width {
						t.Fatalf("%s%s width %d broadcast=%t: %#v", family.name, suffix, width, broadcast, decoded)
					}
				}
			}
		}
	}
}

func TestDecodedX86TernaryLogicCompleteGo127Family(t *testing.T) {
	// Go 1.27 shares _yvalignd between VPTERNLOGD/Q. These LLVM 22 bytes
	// cover X/Y/Z, high registers, memory, masks, zeroing, broadcast, and
	// compressed disp8 for both lane widths.
	tests := []struct {
		name string
		code []byte
		want string
	}{
		{name: "dword x high masked", code: []byte{0x62, 0xa3, 0x55, 0x01, 0x25, 0xf4, 0xca}, want: "VPTERNLOGD $202, X20, X21, K1, X22"},
		{name: "qword y memory zeroing", code: []byte{0x62, 0xd3, 0xf5, 0xaa, 0x25, 0x50, 0x03, 0x96}, want: "VPTERNLOGQ.Z $150, 96(R8), Y1, K2, Y2"},
		{name: "dword reported minio", code: []byte{0x62, 0x73, 0x55, 0x48, 0x25, 0xce, 0xca}, want: "VPTERNLOGD $202, Z6, Z5, Z9"},
		{name: "dword z broadcast high masked", code: []byte{0x62, 0x53, 0x7d, 0x54, 0x25, 0x4c, 0x24, 0x7f, 0x44}, want: "VPTERNLOGD.BCST $68, 508(R12), Z16, K4, Z9"},
		{name: "qword z broadcast zeroing", code: []byte{0x62, 0xf3, 0xf5, 0xdb, 0x25, 0x50, 0x7f, 0x09}, want: "VPTERNLOGQ.BCST.Z $9, 1016(AX), Z1, K3, Z2"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			instruction, length, ok, err := decodedX86TernaryLogicInstruction(test.code, 64)
			if !ok {
				t.Fatal("ternary-logic encoding was not recognized")
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

func TestDecodeX86RawDirectiveGroupReportedMinioVPTERNLOGD(t *testing.T) {
	code := []byte{0x62, 0x73, 0x55, 0x48, 0x25, 0xce, 0xca}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "minio VPTERNLOGD", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || decoded[0].Op != "VPTERNLOGD" || !strings.HasPrefix(decoded[0].Raw, "VPTERNLOGD $202, Z6, Z5, Z9 ") {
		t.Fatalf("decoded reported minio bytes as %#v", decoded)
	}
}
