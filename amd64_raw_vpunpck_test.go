package plan9asm

import "testing"

func TestDecodedX86VPUNPCKInstructionCompleteVEXFamily(t *testing.T) {
	for _, test := range []struct {
		opcode byte
		op     Op
	}{
		{0x60, "VPUNPCKLBW"},
		{0x61, "VPUNPCKLWD"},
		{0x62, "VPUNPCKLDQ"},
		{0x6c, "VPUNPCKLQDQ"},
		{0x68, "VPUNPCKHBW"},
		{0x69, "VPUNPCKHWD"},
		{0x6a, "VPUNPCKHDQ"},
		{0x6d, "VPUNPCKHQDQ"},
	} {
		t.Run(string(test.op), func(t *testing.T) {
			code := []byte{0xc5, 0xe9, test.opcode, 0xcb}
			instruction, length, ok, err := decodedX86VPUNPCKInstruction(code, 64)
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				t.Fatal("encoding was not recognized")
			}
			if length != len(code) {
				t.Fatalf("length = %d, want %d", length, len(code))
			}
			if instruction.Op != test.op || instruction.Raw != string(test.op)+" X3, X2, X1" {
				t.Fatalf("instruction = %#v", instruction)
			}
		})
	}

	for _, test := range []struct {
		name string
		code []byte
		want string
	}{
		{name: "y_memory", code: []byte{0xc5, 0xed, 0x6d, 0x4e, 0x20}, want: "VPUNPCKHQDQ 32(SI), Y2, Y1"},
		{name: "extended_registers", code: []byte{0xc4, 0x41, 0x41, 0x6d, 0xf7}, want: "VPUNPCKHQDQ X15, X7, X14"},
	} {
		t.Run(test.name, func(t *testing.T) {
			instruction, length, ok, err := decodedX86VPUNPCKInstruction(test.code, 64)
			if err != nil {
				t.Fatal(err)
			}
			if !ok || length != len(test.code) || instruction.Raw != test.want {
				t.Fatalf("decode = (%#v, %d, %v), want %q", instruction, length, ok, test.want)
			}
		})
	}
}

func TestDecodedX86VPUNPCKInstructionRejectsInvalidVEXForms(t *testing.T) {
	for _, test := range []struct {
		name string
		code []byte
		mode int
	}{
		{name: "truncated_modrm", code: []byte{0xc5, 0xe9, 0x6d}, mode: 64},
		{name: "vex_pp_zero", code: []byte{0xc5, 0xe8, 0x6d, 0xcb}, mode: 64},
		{name: "vex_w_one", code: []byte{0xc4, 0xe1, 0xe9, 0x6d, 0xcb}, mode: 64},
		{name: "extended_register_in_386", code: []byte{0xc4, 0x41, 0x41, 0x6d, 0xf7}, mode: 32},
		{name: "rip_relative", code: []byte{0xc5, 0xe9, 0x6d, 0x0d, 0, 0, 0, 0}, mode: 64},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, ok, err := decodedX86VPUNPCKInstruction(test.code, test.mode)
			if !ok {
				t.Fatal("VPUNPCK encoding was not recognized")
			}
			if err == nil {
				t.Fatal("invalid encoding was accepted")
			}
		})
	}
}

func TestDecodeX86RawDirectiveGroupVPUNPCKSequence(t *testing.T) {
	code := []byte{
		0xc4, 0xc1, 0x41, 0x6d, 0xf7,
		0xc5, 0x41, 0x6c, 0xff,
		0xc4, 0xc1, 0x11, 0x6d, 0xff,
		0xc5, 0x61, 0x6c, 0xfb,
		0xc4, 0xc1, 0x69, 0x6d, 0xd7,
		0xc4, 0x41, 0x09, 0x6c, 0xfe,
		0xc4, 0xc1, 0x61, 0x6d, 0xdf,
	}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "VPUNPCK raw sequence", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 7 {
		t.Fatalf("decoded %d instructions, want 7: %#v", len(decoded), decoded)
	}
	for _, instruction := range decoded {
		if instruction.Op != "VPUNPCKHQDQ" && instruction.Op != "VPUNPCKLQDQ" {
			t.Fatalf("decoded unexpected op %s", instruction.Op)
		}
	}
}
