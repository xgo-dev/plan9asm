package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// Intel's complete SIGN encoding table is VEX.128/256.66.0F38.WIG.
// Go emits W0. A different ignored W bit must not turn valid physical bytes
// into syntax rejection; neither encoding establishes initialized data/entry.
func TestX86PackedSignPhysicalWIGKeepsCompleteGoOperandIdentity(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		mode := 64
		if arch == "386" {
			mode = 32
		}
		var source strings.Builder
		var expected []byte
		source.WriteString("TEXT SignWIG(SB),4,$0-0\n")
		for index, op := range []string{"VPSIGNB", "VPSIGNW", "VPSIGND"} {
			for width, bank := range []string{"X", "Y"} {
				for _, memory := range []bool{false, true} {
					operand, modrm := bank+"0", byte(0xd0)
					if memory {
						operand, modrm = "(AX)", 0x10
					}
					fmt.Fprintf(&source, "%s %s,%s1,%s2\n", op, operand, bank, bank)
					control := byte(0x71 | width<<2) // logical vvvv=1, 66, no extension bits.
					canonical := []byte{0xc4, 0xe2, control, byte(8 + index), modrm}
					expected = append(expected, canonical...)
					for _, w := range []byte{0, 0x80} {
						code := append([]byte(nil), canonical...)
						code[2] |= w
						ins, length, known, err := decodedX86RawPackedSignInstruction(code, mode)
						if !known || err != nil || length != len(code) || ins.Op != Op(op) || len(ins.Args) != 3 ||
							ins.Args[1].Reg != Reg(bank+"1") || ins.Args[2].Reg != Reg(bank+"2") ||
							(ins.Args[0].Kind == OpMem) != memory || !memory && ins.Args[0].Reg != Reg(bank+"0") {
							t.Fatal("complete physical SIGN WIG class lost actual mode/data/control/destination identity", arch, op, bank, memory, w, ins, err)
						}
					}
				}
			}
		}
		source.WriteString("RET\n")
		expected = append(expected, 0xc3)
		if actual := assembleX87ControlBytes(t, arch, source.String()); !bytes.Equal(actual, expected) {
			t.Fatalf("independent complete Go W0 SIGN bytes differ from physical witness: %s got=%x want=%x", arch, actual, expected)
		}
	}
}

func TestX86PackedAbsPhysicalVEXWIGAndFixedEVEXWidth(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		mode := 64
		if arch == "386" {
			mode = 32
		}
		var source strings.Builder
		var expected []byte
		source.WriteString("TEXT AbsWIG(SB),4,$0-0\n")
		for index, op := range []string{"VPABSB", "VPABSW", "VPABSD"} {
			for width, bank := range []string{"X", "Y"} {
				for _, memory := range []bool{false, true} {
					operand, modrm := bank+"0", byte(0xd0)
					if memory {
						operand, modrm = "(AX)", 0x10
					}
					fmt.Fprintf(&source, "%s %s,%s2\n", op, operand, bank)
					canonical := []byte{0xc4, 0xe2, byte(0x79 | width<<2), byte(0x1c + index), modrm}
					expected = append(expected, canonical...)
					for _, w := range []byte{0, 0x80} {
						code := append([]byte(nil), canonical...)
						code[2] |= w
						ins, length, known, err := decodedX86RawPackedAbsInstruction(code, mode)
						if !known || err != nil || length != len(code) || ins.Op != Op(op) || len(ins.Args) != 2 ||
							ins.Args[1].Reg != Reg(bank+"2") || (ins.Args[0].Kind == OpMem) != memory ||
							!memory && ins.Args[0].Reg != Reg(bank+"0") {
							t.Fatal("VEX ABS WIG lost complete operand identity", arch, op, bank, memory, w, ins, err)
						}
					}
				}
			}
		}
		source.WriteString("RET\n")
		expected = append(expected, 0xc3)
		if actual := assembleX87ControlBytes(t, arch, source.String()); !bytes.Equal(actual, expected) {
			t.Fatalf("independent complete Go W0 ABS witness differs: %s got=%x want=%x", arch, actual, expected)
		}
		for index := 0; index < 4; index++ {
			code := encodeX86RawPackedAbs(index, 64, 1, 2, 0, false, false)
			if _, _, known, err := decodedX86RawPackedAbsInstruction(code, mode); !known || err != nil {
				t.Fatal("canonical EVEX ABS W0/W1 rejected", index, arch, err)
			}
			code[2] ^= 0x80
			if _, _, known, err := decodedX86RawPackedAbsInstruction(code, mode); !known || err == nil {
				t.Fatal("VEX WIG rule incorrectly widened fixed EVEX W", index, arch)
			}
		}
	}
}

func TestX86PackedAbsSignTypedGrammarRejectsNonGoForms(t *testing.T) {
	for _, line := range []string{
		"PABSQ X0,X1", "PABSB M0,M1", "PSIGNW M0,M1", "PABSD.Z X0,X1",
		"VPABSB.BCST (AX),X1", "VPABSW.BCST (AX),Y1", "VPABSQ.BCST X0,X1",
		"VPABSD X0,Y1", "VPABSQ X0,K0,X1", "VPABSB.Z X0,X1",
		"VPSIGNB Z0,Z1,Z2", "VPSIGND X0,K1,X1", "VPSIGNW.Z X0,X1,X2", "VPSIGND.BCST (AX),X1,X2",
	} {
		t.Run(strings.ReplaceAll(line, " ", "_"), func(t *testing.T) {
			ins := x86ScalarLaneInstruction(t, line)
			_, known, err := x86TypedInstructionByteEffect(ins.Op, ins, "amd64")
			wantKnown := !strings.HasPrefix(line, "PABSQ ") // No legacy qword ABS opcode exists.
			if known != wantKnown || known && err == nil {
				t.Fatal("known ABS/sign family lacks a closed typed syntax boundary", line, known, err)
			}
		})
	}
}
