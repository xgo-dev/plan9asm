package plan9asm

import (
	"reflect"
	"testing"
)

func TestX86RawVEXPackedIntegerMoveCorpusEncoding(t *testing.T) {
	const source = "TEXT corpusmove(SB),4,$0-0\n\tVMOVDQU -32(SI)(CX*4), Y14\n\tRET\n"
	code := assembleX87ControlBytes(t, "amd64", source)
	decoded, err := decodeX86RawDirectives(rawX86Function(code), "amd64")
	if err != nil {
		t.Fatal(err)
	}
	named, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	want := named.Funcs[0].Instrs[1:]
	if len(decoded.Instrs) != len(want) {
		t.Fatalf("decoded %d instructions, want %d", len(decoded.Instrs), len(want))
	}
	for i, got := range decoded.Instrs {
		if got.Op != want[i].Op || !reflect.DeepEqual(got.Args, want[i].Args) {
			t.Fatalf("instruction %d=%+v, want %+v", i, got, want[i])
		}
	}
}

func TestX86RawVEXPackedIntegerMoveRejectsReservedForms(t *testing.T) {
	for _, test := range []struct {
		name string
		code []byte
		mode int
	}{
		{"missing ModRM", []byte{0xc5, 0xfe, 0x6f}, 64},
		{"missing SIB", []byte{0xc5, 0xfe, 0x6f, 0x04}, 64},
		{"missing displacement", []byte{0xc5, 0xfe, 0x6f, 0x44, 0x24}, 64},
		{"reserved vvvv", []byte{0xc5, 0xf6, 0x6f, 0xc0}, 64},
		{"extended register in 386", []byte{0xc5, 0x7e, 0x6f, 0xc0}, 32},
		{"address override", []byte{0x67, 0xc5, 0xfe, 0x6f, 0xc0}, 64},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, matched, err := decodedX86PackedMoveInstruction(test.code, test.mode); !matched || err == nil {
				t.Fatalf("invalid %x: matched=%v err=%v", test.code, matched, err)
			}
		})
	}
}

func TestX86RawVEXPackedIntegerMoveIgnoresWBit(t *testing.T) {
	for _, code := range [][]byte{
		{0xc4, 0xe1, 0x7e, 0x6f, 0xc0},
		{0xc4, 0xe1, 0xfe, 0x6f, 0xc0},
	} {
		got, size, matched, err := decodedX86PackedMoveInstruction(code, 64)
		if err != nil || !matched || size != len(code) || got.Op != "VMOVDQU" ||
			!reflect.DeepEqual(got.Args, []Operand{{Kind: OpReg, Reg: "Y0"}, {Kind: OpReg, Reg: "Y0"}}) {
			t.Fatalf("decode %x=%+v size=%d matched=%v err=%v", code, got, size, matched, err)
		}
	}
}
