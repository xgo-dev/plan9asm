package plan9asm

import (
	"strings"
	"testing"
)

func TestDecodedX86SHACompleteGo127Family(t *testing.T) {
	// Go 1.27 exposes every Intel SHA extension opcode. Cover register and
	// memory sources, REX-extended X registers, the SHA1 immediate, and the
	// implicit X0 operand used by SHA256RNDS2.
	tests := []struct {
		name string
		code []byte
		want string
	}{
		{name: "sha1 next e", code: []byte{0x0f, 0x38, 0xc8, 0xca}, want: "SHA1NEXTE X2, X1"},
		{name: "sha1 message 1 high destination", code: []byte{0x44, 0x0f, 0x38, 0xc9, 0xf4}, want: "SHA1MSG1 X4, X14"},
		{name: "sha1 message 2 memory", code: []byte{0x41, 0x0f, 0x38, 0xca, 0x54, 0x8c, 0x20}, want: "SHA1MSG2 32(R12)(CX*4), X2"},
		{name: "sha256 message 1", code: []byte{0x0f, 0x38, 0xcc, 0xe5}, want: "SHA256MSG1 X5, X4"},
		{name: "sha256 message 2", code: []byte{0x0f, 0x38, 0xcd, 0xf5}, want: "SHA256MSG2 X5, X6"},
		{name: "sha1 rounds 4", code: []byte{0x0f, 0x3a, 0xcc, 0xd1, 0x03}, want: "SHA1RNDS4 $3, X1, X2"},
		{name: "sha256 rounds 2 implicit x0", code: []byte{0x0f, 0x38, 0xcb, 0xda}, want: "SHA256RNDS2 X0, X2, X3"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			instruction, length, ok, err := decodedX86SHAInstruction(test.code, 64)
			if !ok {
				t.Fatal("SHA encoding was not recognized")
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

func TestDecodeX86RawDirectiveGroupReportedMinioSHA256RNDS2(t *testing.T) {
	code := []byte{0x0f, 0x38, 0xcb, 0xda}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "minio SHA256RNDS2", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || decoded[0].Op != "SHA256RNDS2" || !strings.HasPrefix(decoded[0].Raw, "SHA256RNDS2 X0, X2, X3 ") {
		t.Fatalf("decoded reported minio bytes as %#v", decoded)
	}
}
