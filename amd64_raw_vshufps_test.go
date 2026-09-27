package plan9asm

import (
	"strings"
	"testing"
)

func TestDecodedX86VSHUFPSInstructionCompleteVEXForms(t *testing.T) {
	tests := []struct {
		name string
		code []byte
		mode int
		want string
	}{
		{name: "x_register", code: []byte{0xc5, 0x78, 0xc6, 0xc1, 0x44}, mode: 64, want: "VSHUFPS $68, X1, X0, X8"},
		{name: "y_register", code: []byte{0xc5, 0x6c, 0xc6, 0xcb, 0x44}, mode: 64, want: "VSHUFPS $68, Y3, Y2, Y9"},
		{name: "extended_registers", code: []byte{0xc4, 0x41, 0x3c, 0xc6, 0xd1, 0xdd}, mode: 64, want: "VSHUFPS $221, Y9, Y8, Y10"},
		{name: "memory_disp8", code: []byte{0xc5, 0xec, 0xc6, 0x56, 0x20, 0x01}, mode: 64, want: "VSHUFPS $1, 32(SI), Y2, Y2"},
		{name: "pd extended registers", code: []byte{0xc4, 0x41, 0x3d, 0xc6, 0xd1, 0xdd}, mode: 64, want: "VSHUFPD $221, Y9, Y8, Y10"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			instruction, length, ok, err := decodedX86VSHUFPSInstruction(test.code, test.mode)
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				t.Fatal("encoding was not recognized")
			}
			if length != len(test.code) {
				t.Fatalf("length = %d, want %d", length, len(test.code))
			}
			if instruction.Raw != test.want {
				t.Fatalf("instruction = %q, want %q", instruction.Raw, test.want)
			}
		})
	}
}

func TestDecodedX86PackedFloatShuffleCompleteEVEXFamily(t *testing.T) {
	// Go 1.27 assigns VSHUFPS and VSHUFPD the shared
	// _yvgf2p8affineinvqb table. Its EVEX rows cover X/Y/Z register or
	// memory sources, high registers, K masking, zeroing, and scalar
	// broadcast. The byte sequences below are verified by LLVM 22.
	tests := []struct {
		name string
		code []byte
		want string
	}{
		{name: "ps x high masked", code: []byte{0x62, 0xa1, 0x54, 0x01, 0xc6, 0xf4, 0x06}, want: "VSHUFPS $6, X20, X21, K1, X22"},
		{name: "ps y memory zeroing", code: []byte{0x62, 0xd1, 0x74, 0xaa, 0xc6, 0x50, 0x03, 0x07}, want: "VSHUFPS.Z $7, 96(R8), Y1, K2, Y2"},
		{name: "ps z high", code: []byte{0x62, 0x31, 0x7c, 0x40, 0xc6, 0xc9, 0x44}, want: "VSHUFPS $68, Z17, Z16, Z9"},
		{name: "ps z broadcast zeroing", code: []byte{0x62, 0xf1, 0x74, 0xdb, 0xc6, 0x50, 0x7f, 0x09}, want: "VSHUFPS.BCST.Z $9, 508(AX), Z1, K3, Z2"},
		{name: "pd x high masked", code: []byte{0x62, 0xa1, 0xd5, 0x01, 0xc6, 0xf4, 0x06}, want: "VSHUFPD $6, X20, X21, K1, X22"},
		{name: "pd y memory zeroing", code: []byte{0x62, 0xd1, 0xf5, 0xaa, 0xc6, 0x50, 0x03, 0x07}, want: "VSHUFPD.Z $7, 96(R8), Y1, K2, Y2"},
		{name: "pd z high", code: []byte{0x62, 0x31, 0xfd, 0x40, 0xc6, 0xc9, 0x44}, want: "VSHUFPD $68, Z17, Z16, Z9"},
		{name: "pd z broadcast zeroing", code: []byte{0x62, 0xf1, 0xf5, 0xdb, 0xc6, 0x50, 0x7f, 0x09}, want: "VSHUFPD.BCST.Z $9, 1016(AX), Z1, K3, Z2"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			instruction, length, ok, err := decodedX86VSHUFPSInstruction(test.code, 64)
			if !ok {
				t.Fatal("packed float shuffle encoding was not recognized")
			}
			if err != nil {
				t.Fatal(err)
			}
			if length != len(test.code) {
				t.Fatalf("decoded length = %d, want %d", length, len(test.code))
			}
			if instruction.Raw != test.want {
				t.Fatalf("decoded %x as %q, want %q", test.code, instruction.Raw, test.want)
			}
		})
	}
}

func TestDecodeX86RawDirectiveGroupReportedMinioEVEXVSHUFPS(t *testing.T) {
	code := []byte{0x62, 0x31, 0x7c, 0x40, 0xc6, 0xc9, 0x44}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "minio EVEX VSHUFPS", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || decoded[0].Op != "VSHUFPS" || !strings.HasPrefix(decoded[0].Raw, "VSHUFPS $68, Z17, Z16, Z9 ") {
		t.Fatalf("decoded reported minio bytes as %#v", decoded)
	}
}

func TestDecodedX86VSHUFPSInstructionRejectsInvalidVEXForms(t *testing.T) {
	tests := []struct {
		name string
		code []byte
		mode int
	}{
		{name: "truncated_modrm", code: []byte{0xc5, 0x7c, 0xc6}, mode: 64},
		{name: "truncated_immediate", code: []byte{0xc5, 0x7c, 0xc6, 0xc1}, mode: 64},
		{name: "vex_pp_f3", code: []byte{0xc5, 0x7e, 0xc6, 0xc1, 0x44}, mode: 64},
		{name: "vex_w_one", code: []byte{0xc4, 0xe1, 0xbc, 0xc6, 0xc1, 0x44}, mode: 64},
		{name: "extended_register_in_386", code: []byte{0xc5, 0x78, 0xc6, 0xc1, 0x44}, mode: 32},
		{name: "rip_relative", code: []byte{0xc5, 0xfc, 0xc6, 0x05, 0, 0, 0, 0, 0x44}, mode: 64},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, ok, err := decodedX86VSHUFPSInstruction(test.code, test.mode)
			if !ok {
				t.Fatal("VSHUFPS encoding was not recognized")
			}
			if err == nil {
				t.Fatal("invalid encoding was accepted")
			}
		})
	}
}

func TestDecodeX86RawDirectiveGroupVSHUFPSSequence(t *testing.T) {
	code := []byte{
		0xc5, 0x7c, 0xc6, 0xc1, 0x44,
		0xc5, 0xfc, 0xc6, 0xc1, 0xee,
		0xc5, 0x6c, 0xc6, 0xcb, 0x44,
		0xc5, 0xec, 0xc6, 0xd3, 0xee,
		0xc4, 0xc1, 0x3c, 0xc6, 0xd9, 0xdd,
	}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "VSHUFPS raw sequence", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 5 {
		t.Fatalf("decoded %d instructions, want 5: %#v", len(decoded), decoded)
	}
	for _, instruction := range decoded {
		if instruction.Op != "VSHUFPS" {
			t.Fatalf("decoded op = %s, want VSHUFPS", instruction.Op)
		}
	}
}
