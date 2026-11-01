package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateRawVEXVMOVDWeaviateRegression(t *testing.T) {
	const source = `TEXT rawVMOVD(SB), $0-0
	LONG $0x7e79c1c4
	BYTE $0xc7
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{"rawVMOVD": {Name: "rawVMOVD", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "extractelement <4 x i32>") {
		t.Fatalf("raw VMOVD lowering omitted scalar extraction:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "amd64-raw-vex-vmovd.ll", "amd64-raw-vex-vmovd.o", ir)
}

func TestDecodedX86VMOVQInstructionCompleteVEXForms(t *testing.T) {
	tests := []struct {
		name string
		code []byte
		want string
	}{
		{name: "x_to_gp", code: []byte{0xc4, 0xe1, 0xf9, 0x7e, 0xc8}, want: "VMOVQ X1, AX"},
		{name: "x_to_x", code: []byte{0xc4, 0xe1, 0x79, 0xd6, 0xc8}, want: "VMOVQ X1, X0"},
		{name: "gp_to_x", code: []byte{0xc4, 0xe1, 0xf9, 0x6e, 0xc8}, want: "VMOVQ AX, X1"},
		{name: "x_to_x_f3", code: []byte{0xc5, 0xfa, 0x7e, 0xc8}, want: "VMOVQ X0, X1"},
		{name: "memory_to_extended_x", code: []byte{0xc5, 0x7a, 0x7e, 0x5e, 0x20}, want: "VMOVQ 32(SI), X11"},
		{name: "extended_x_to_sib_memory", code: []byte{0xc4, 0x21, 0xf9, 0x7e, 0x94, 0x8c, 0x78, 0x56, 0x34, 0x12}, want: "VMOVQ X10, 305419896(SP)(R9*4)"},
		{name: "reported_weaviate_vmovd", code: []byte{0xc4, 0xc1, 0x79, 0x7e, 0xc7}, want: "VMOVD X0, R15"},
		{name: "vmovd_extended_gp_to_x", code: []byte{0xc4, 0xc1, 0x79, 0x6e, 0xcf}, want: "VMOVD R15, X1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			instruction, length, ok, err := decodedX86VMOVQInstruction(test.code, 64)
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

func encodeX86VEXVMOVDQ(opcode, pp byte, vex3, width64 bool, vector, rm int) []byte {
	modRM := byte(0xc0 | (vector&7)<<3 | rm&7)
	if !vex3 {
		vex1 := byte((1-vector/8)<<7 | 15<<3 | int(pp))
		return []byte{0xc5, vex1, opcode, modRM}
	}
	vex0 := byte((1-vector/8)<<7 | 1<<6 | (1-rm/8)<<5 | 1)
	vex1 := byte(15<<3 | int(pp))
	if width64 {
		vex1 |= 0x80
	}
	return []byte{0xc4, vex0, vex1, opcode, modRM}
}

func TestDecodedX86VMOVDQCompleteVEXRegisterFamily(t *testing.T) {
	tests := []struct {
		opcode   byte
		pp       byte
		width64  bool
		op       Op
		reverse  bool
		vectorRM bool
		vex2     bool
	}{
		{opcode: 0x7e, pp: 1, op: "VMOVD", vex2: true},
		{opcode: 0x6e, pp: 1, op: "VMOVD", reverse: true, vex2: true},
		{opcode: 0x7e, pp: 1, width64: true, op: "VMOVQ"},
		{opcode: 0xd6, pp: 1, op: "VMOVQ", vectorRM: true, vex2: true},
		{opcode: 0x6e, pp: 1, width64: true, op: "VMOVQ", reverse: true},
		{opcode: 0x7e, pp: 2, op: "VMOVQ", reverse: true, vectorRM: true, vex2: true},
	}
	count := 0
	for _, test := range tests {
		for _, vex3 := range []bool{false, true} {
			if !vex3 && !test.vex2 {
				continue
			}
			rmLimit := 16
			if !vex3 {
				rmLimit = 8
			}
			for vector := 0; vector < 16; vector++ {
				for rm := 0; rm < rmLimit; rm++ {
					code := encodeX86VEXVMOVDQ(test.opcode, test.pp, vex3, test.width64, vector, rm)
					got, length, ok, err := decodedX86VMOVQInstruction(code, 64)
					if err != nil || !ok || length != len(code) {
						t.Fatalf("decode %x returned %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
					}
					rmName := fmt.Sprintf("R%d", rm)
					if rm < 8 {
						rmName = [...]string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"}[rm]
					}
					if test.vectorRM {
						rmName = fmt.Sprintf("X%d", rm)
					}
					wantArgs := []string{fmt.Sprintf("X%d", vector), rmName}
					if test.reverse {
						wantArgs[0], wantArgs[1] = wantArgs[1], wantArgs[0]
					}
					if got.Op != test.op || len(got.Args) != 2 || got.Args[0].String() != wantArgs[0] || got.Args[1].String() != wantArgs[1] {
						t.Fatalf("decode %x = %+v, want %s %s", code, got, test.op, strings.Join(wantArgs, ", "))
					}
					count++
				}
			}
		}
	}
	if count != 2048 {
		t.Fatalf("covered %d VEX VMOVD/VMOVQ register encodings, want 2048", count)
	}
}

func TestDecodedX86VMOVDQCompleteGo127EVEXForms(t *testing.T) {
	tests := []struct {
		name string
		code []byte
		want string
	}{
		{name: "d high x to gp", code: []byte{0x62, 0x61, 0x7d, 0x08, 0x7e, 0xf8}, want: "VMOVD X31, AX"},
		{name: "d gp to high x", code: []byte{0x62, 0x61, 0x7d, 0x08, 0x6e, 0xf8}, want: "VMOVD AX, X31"},
		{name: "q high x to gp", code: []byte{0x62, 0x61, 0xfd, 0x08, 0x7e, 0xf8}, want: "VMOVQ X31, AX"},
		{name: "q x to high x", code: []byte{0x62, 0x91, 0xfd, 0x08, 0xd6, 0xc7}, want: "VMOVQ X0, X31"},
		{name: "q gp to high x", code: []byte{0x62, 0x61, 0xfd, 0x08, 0x6e, 0xf8}, want: "VMOVQ AX, X31"},
		{name: "q high x to x alternate", code: []byte{0x62, 0xf1, 0xfe, 0x08, 0x7e, 0xc7}, want: "VMOVQ X7, X0"},
		{name: "d high x to compressed memory", code: []byte{0x62, 0x61, 0x7d, 0x08, 0x7e, 0x78, 0x7f}, want: "VMOVD X31, 508(AX)"},
		{name: "q compressed memory to high x", code: []byte{0x62, 0x61, 0xfd, 0x08, 0x6e, 0x78, 0x7f}, want: "VMOVQ 1016(AX), X31"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			instruction, length, ok, err := decodedX86VMOVQInstruction(test.code, 64)
			if err != nil {
				t.Fatal(err)
			}
			if !ok || length != len(test.code) || instruction.Raw != test.want {
				t.Fatalf("decoded %x as %+v length=%d ok=%v, want %q", test.code, instruction, length, ok, test.want)
			}
		})
	}
}

func TestDecodedX86VMOVQInstructionRejectsInvalidVEXForms(t *testing.T) {
	tests := []struct {
		name string
		code []byte
		mode int
	}{
		{name: "truncated_modrm", code: []byte{0xc5, 0xfa, 0x7e}, mode: 64},
		{name: "vex_l_one", code: []byte{0xc5, 0xfe, 0x7e, 0xc8}, mode: 64},
		{name: "used_vvvv", code: []byte{0xc5, 0xf2, 0x7e, 0xc8}, mode: 64},
		{name: "w_one_in_386", code: []byte{0xc4, 0xe1, 0xf9, 0x6e, 0xc8}, mode: 32},
		{name: "extended_register_in_386", code: []byte{0xc5, 0x7a, 0x7e, 0xc0}, mode: 32},
		{name: "rip_relative", code: []byte{0xc5, 0xfa, 0x7e, 0x05, 0, 0, 0, 0}, mode: 64},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, ok, err := decodedX86VMOVQInstruction(test.code, test.mode)
			if !ok {
				t.Fatal("VMOVQ-family encoding was not recognized")
			}
			if err == nil {
				t.Fatal("invalid encoding was accepted")
			}
		})
	}
}
