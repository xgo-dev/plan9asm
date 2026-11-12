package plan9asm

import "testing"

func TestDecodedX86VPERMQInstructionCompleteVEXForms(t *testing.T) {
	tests := []struct {
		name string
		code []byte
		mode int
		want string
	}{
		{name: "register", code: []byte{0xc4, 0xe3, 0xfd, 0x00, 0xc9, 0x39}, mode: 64, want: "VPERMQ $57, Y1, Y1"},
		{name: "extended_registers", code: []byte{0xc4, 0x43, 0xfd, 0x00, 0xca, 0xff}, mode: 64, want: "VPERMQ $255, Y10, Y9"},
		{name: "memory_disp8", code: []byte{0xc4, 0xe3, 0xfd, 0x00, 0x4e, 0x20, 0x01}, mode: 64, want: "VPERMQ $1, 32(SI), Y1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			instruction, length, ok, err := decodedX86VPERMQInstruction(test.code, test.mode)
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

func TestDecodedX86VPERMQInstructionRejectsInvalidVEXForms(t *testing.T) {
	tests := []struct {
		name string
		code []byte
		mode int
	}{
		{name: "truncated_modrm", code: []byte{0xc4, 0xe3, 0xfd, 0x00}, mode: 64},
		{name: "truncated_immediate", code: []byte{0xc4, 0xe3, 0xfd, 0x00, 0xc9}, mode: 64},
		{name: "vex_l_zero", code: []byte{0xc4, 0xe3, 0xf9, 0x00, 0xc9, 0x39}, mode: 64},
		{name: "used_vvvv", code: []byte{0xc4, 0xe3, 0xed, 0x00, 0xc9, 0x39}, mode: 64},
		{name: "extended_register_in_386", code: []byte{0xc4, 0x43, 0xfd, 0x00, 0xca, 0xff}, mode: 32},
		{name: "rip_relative", code: []byte{0xc4, 0xe3, 0xfd, 0x00, 0x0d, 0, 0, 0, 0, 0x39}, mode: 64},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, ok, err := decodedX86VPERMQInstruction(test.code, test.mode)
			if !ok {
				t.Fatal("VPERMQ encoding was not recognized")
			}
			if err == nil {
				t.Fatal("invalid encoding was accepted")
			}
		})
	}
}

func TestDecodeX86RawDirectiveGroupVPERMQSequence(t *testing.T) {
	code := []byte{
		0xc4, 0xe3, 0xfd, 0x00, 0xc9, 0x39,
		0xc4, 0xe3, 0xfd, 0x00, 0xd2, 0x4e,
		0xc4, 0xe3, 0xfd, 0x00, 0xdb, 0x93,
	}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "VPERMQ raw sequence", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 3 {
		t.Fatalf("decoded %d instructions, want 3: %#v", len(decoded), decoded)
	}
	for _, instruction := range decoded {
		if instruction.Op != "VPERMQ" {
			t.Fatalf("decoded op = %s, want VPERMQ", instruction.Op)
		}
	}
}
