package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86RawExplicitMaskMoveGoEncoderForms(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT rawmaskmoveforms(SB),4,$0-0\n")
			for _, op := range []string{"VMASKMOVPS", "VMASKMOVPD", "VPMASKMOVD", "VPMASKMOVQ"} {
				for _, width := range []string{"X", "Y"} {
					for _, reg := range []int{1, 7, 15} {
						fmt.Fprintf(&source, "%s 8(AX), %s2, %s%d\n", op, width, width, reg)
						fmt.Fprintf(&source, "%s %s%d, %s2, 16(BX)\n", op, width, reg, width)
					}
				}
			}
			source.WriteString("RET\n")
			code := assembleX87ControlBytes(t, arch, source.String())
			decoded, err := decodeX86RawDirectives(rawX86Function(code), arch)
			if err != nil {
				t.Fatal(err)
			}
			named, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			want := named.Funcs[0].Instrs[1:]
			if len(decoded.Instrs) != len(want) {
				t.Fatalf("decoded %d instructions, want %d", len(decoded.Instrs), len(want))
			}
			for index, got := range decoded.Instrs {
				if got.Op != want[index].Op || !reflect.DeepEqual(got.Args, want[index].Args) {
					t.Fatalf("instruction %d = %s %v, want %s %v", index, got.Op, got.Args, want[index].Op, want[index].Args)
				}
			}
			if len(code) == 0 || code[len(code)-1] != 0xc3 {
				t.Fatal("Go assembler did not end the fixture with RET")
			}
			var raw strings.Builder
			raw.WriteString("TEXT rawmaskmoveforms(SB),4,$0-0\n")
			for _, value := range code[:len(code)-1] {
				fmt.Fprintf(&raw, "BYTE $%#02x\n", value)
			}
			raw.WriteString("RET\n")
			file, err := Parse(ArchAMD64, raw.String())
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			triples := []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"}
			if arch == "386" {
				triples = []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"}
			}
			for _, triple := range triples {
				ir, err := Translate(file, Options{
					Goarch: arch, TargetTriple: triple,
					Sigs: map[string]FuncSig{"rawmaskmoveforms": {Name: "rawmaskmoveforms", Ret: Void}},
				})
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, triple, "raw-explicit-mask-move.ll", "raw-explicit-mask-move.o", ir)
			}
		})
	}
}

func TestX86RawExplicitMaskMoveRejectsInvalidEncodings(t *testing.T) {
	for _, test := range []struct {
		name string
		code []byte
	}{
		{name: "missing ModRM", code: []byte{0xc4, 0xa2, 0x69, 0x8e}},
		{name: "register destination", code: []byte{0xc4, 0xe2, 0x69, 0x8e, 0xc1}},
		{name: "wrong pp", code: []byte{0xc4, 0xa2, 0x68, 0x8e, 0x0c, 0x82}},
		{name: "floating W1", code: []byte{0xc4, 0xe2, 0xe9, 0x2c, 0x01}},
		{name: "address override", code: []byte{0x67, 0xc4, 0xa2, 0x69, 0x8e, 0x0c, 0x82}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, matched, err := decodedX86ExplicitMaskMoveInstruction(test.code, 64); !matched || err == nil {
				t.Fatalf("invalid %x matched=%v error=%v", test.code, matched, err)
			}
		})
	}
	for _, code := range [][]byte{
		{0xc4, 0xe3, 0x69, 0x8e, 0xc1},
		{0x62, 0xe2, 0x69, 0x08, 0x8e, 0xc1},
	} {
		if _, _, matched, err := decodedX86ExplicitMaskMoveInstruction(code, 64); matched || err != nil {
			t.Fatalf("other opcode %x matched=%v error=%v", code, matched, err)
		}
	}
}
