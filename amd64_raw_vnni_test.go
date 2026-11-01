package plan9asm

import "testing"

func TestDecodedX86VNNIInstructionCompleteVEXFamily(t *testing.T) {
	for _, test := range []struct {
		opcode byte
		op     Op
	}{
		{0x50, "VPDPBUSD"},
		{0x51, "VPDPBUSDS"},
		{0x52, "VPDPWSSD"},
		{0x53, "VPDPWSSDS"},
	} {
		t.Run(string(test.op), func(t *testing.T) {
			code := []byte{0xc4, 0xe2, 0x71, test.opcode, 0xc2}
			instruction, length, ok, err := decodedX86VNNIInstruction(code, 64)
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				t.Fatal("encoding was not recognized")
			}
			if length != len(code) {
				t.Fatalf("length = %d, want %d", length, len(code))
			}
			want := string(test.op) + " X2, X1, X0"
			if instruction.Op != test.op || instruction.Raw != want {
				t.Fatalf("instruction = %#v, want %q", instruction, want)
			}
		})
	}

	for _, test := range []struct {
		name string
		code []byte
		mode int
		want string
	}{
		{
			name: "y_extended_registers",
			code: []byte{0xc4, 0x42, 0x15, 0x50, 0xdc},
			mode: 64,
			want: "VPDPBUSD Y12, Y13, Y11",
		},
		{
			name: "x_memory_sib_disp8",
			code: []byte{0xc4, 0x62, 0x11, 0x50, 0x5c, 0x88, 0x20},
			mode: 64,
			want: "VPDPBUSD 32(AX)(CX*4), X13, X11",
		},
		{
			name: "y_memory_negative_disp8",
			code: []byte{0xc4, 0x62, 0x65, 0x51, 0x64, 0x35, 0xef},
			mode: 64,
			want: "VPDPBUSDS -17(BP)(SI*1), Y3, Y12",
		},
		{
			name: "x_memory_extended_address",
			code: []byte{0xc4, 0x82, 0x39, 0x52, 0x74, 0x7e, 0x07},
			mode: 64,
			want: "VPDPWSSD 7(R14)(R15*2), X8, X6",
		},
		{
			name: "y_386_memory",
			code: []byte{0xc4, 0xe2, 0x65, 0x53, 0x64, 0x35, 0xef},
			mode: 32,
			want: "VPDPWSSDS -17(BP)(SI*1), Y3, Y4",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			instruction, length, ok, err := decodedX86VNNIInstruction(test.code, test.mode)
			if err != nil {
				t.Fatal(err)
			}
			if !ok || length != len(test.code) || instruction.Raw != test.want {
				t.Fatalf("decode = (%#v, %d, %v), want %q", instruction, length, ok, test.want)
			}
		})
	}
}

func TestDecodedX86VNNIInstructionRejectsInvalidVEXForms(t *testing.T) {
	for _, test := range []struct {
		name string
		code []byte
		mode int
	}{
		{name: "truncated_modrm", code: []byte{0xc4, 0xe2, 0x71, 0x50}, mode: 64},
		{name: "vex_pp_zero", code: []byte{0xc4, 0xe2, 0x70, 0x50, 0xc2}, mode: 64},
		{name: "vex_w_one", code: []byte{0xc4, 0xe2, 0xf1, 0x50, 0xc2}, mode: 64},
		{name: "address_override", code: []byte{0x67, 0xc4, 0xe2, 0x71, 0x50, 0xc2}, mode: 64},
		{name: "extended_register_in_386", code: []byte{0xc4, 0x42, 0x15, 0x50, 0xdc}, mode: 32},
		{name: "rip_relative", code: []byte{0xc4, 0xe2, 0x71, 0x50, 0x05, 0, 0, 0, 0}, mode: 64},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, ok, err := decodedX86VNNIInstruction(test.code, test.mode)
			if !ok {
				t.Fatal("VNNI encoding was not recognized")
			}
			if err == nil {
				t.Fatal("invalid encoding was accepted")
			}
		})
	}
}

func TestDecodeX86RawDirectiveGroupVNNIReportedSequence(t *testing.T) {
	code := []byte{
		0xc4, 0x42, 0x15, 0x50, 0xdc,
		0xc4, 0x62, 0x7d, 0x50, 0xc7,
	}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "go-pherence VEX VNNI sequence", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 {
		t.Fatalf("decoded %d instructions, want 2: %#v", len(decoded), decoded)
	}
	for _, instruction := range decoded {
		if instruction.Op != "VPDPBUSD" {
			t.Fatalf("decoded op = %s, want VPDPBUSD", instruction.Op)
		}
	}
}
