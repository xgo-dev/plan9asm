package plan9asm

import "testing"

func TestDecodedX86VPINSRInstructionCompleteVEXFamily(t *testing.T) {
	tests := []struct {
		name string
		code []byte
		mode int
		want string
	}{
		{name: "byte_register", code: []byte{0xc4, 0xe3, 0x79, 0x20, 0xc1, 0x02}, mode: 64, want: "VPINSRB $2, CX, X0, X0"},
		{name: "word_two_byte_vex", code: []byte{0xc5, 0xf9, 0xc4, 0xc1, 0x02}, mode: 64, want: "VPINSRW $2, CX, X0, X0"},
		{name: "dword_register", code: []byte{0xc4, 0xe3, 0x79, 0x22, 0xc1, 0x02}, mode: 64, want: "VPINSRD $2, CX, X0, X0"},
		{name: "qword_register", code: []byte{0xc4, 0xe3, 0xf9, 0x22, 0xc1, 0x02}, mode: 64, want: "VPINSRQ $2, CX, X0, X0"},
		{name: "qword_memory_disp8", code: []byte{0xc4, 0x63, 0xa1, 0x22, 0x5e, 0x28, 0x01}, mode: 64, want: "VPINSRQ $1, 40(SI), X11, X11"},
		{name: "extended_registers", code: []byte{0xc4, 0x43, 0x31, 0x22, 0xca, 0x01}, mode: 64, want: "VPINSRD $1, R10, X9, X9"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			instruction, length, ok, err := decodedX86VPINSRInstruction(test.code, test.mode)
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

func TestDecodedX86VPINSRInstructionRejectsInvalidVEXForms(t *testing.T) {
	tests := []struct {
		name string
		code []byte
		mode int
	}{
		{name: "truncated_modrm", code: []byte{0xc4, 0xe3, 0xf9, 0x22}, mode: 64},
		{name: "truncated_immediate", code: []byte{0xc4, 0xe3, 0xf9, 0x22, 0xc1}, mode: 64},
		{name: "vex_l_one", code: []byte{0xc4, 0xe3, 0xfd, 0x22, 0xc1, 0x02}, mode: 64},
		{name: "vex_pp_zero", code: []byte{0xc4, 0xe3, 0xf8, 0x22, 0xc1, 0x02}, mode: 64},
		{name: "qword_in_386", code: []byte{0xc4, 0xe3, 0xf9, 0x22, 0xc1, 0x02}, mode: 32},
		{name: "extended_register_in_386", code: []byte{0xc4, 0x43, 0x31, 0x22, 0xca, 0x01}, mode: 32},
		{name: "rip_relative", code: []byte{0xc4, 0xe3, 0xf9, 0x22, 0x05, 0, 0, 0, 0, 0x02}, mode: 64},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, ok, err := decodedX86VPINSRInstruction(test.code, test.mode)
			if !ok {
				t.Fatal("VPINSR encoding was not recognized")
			}
			if err == nil {
				t.Fatal("invalid encoding was accepted")
			}
		})
	}
}

func TestDecodeX86RawDirectiveGroupVPINSRQSequence(t *testing.T) {
	code := []byte{0xc4, 0x63, 0xa1, 0x22, 0x5e, 0x28, 0x01}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "VPINSRQ raw sequence", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || decoded[0].Op != "VPINSRQ" {
		t.Fatalf("decoded = %#v, want one VPINSRQ", decoded)
	}
}
