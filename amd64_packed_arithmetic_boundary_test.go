package plan9asm

import (
	"fmt"
	"testing"
)

func TestX86PackedArithmeticFamilyMissesStayEmpty(t *testing.T) {
	for _, row := range []struct {
		op       Op
		families x86PackedArithmeticFamily
	}{
		{"MOVQ", 0},
		{"VPADDB", x86PackedArithmeticSubtract},
		{"VPSUBD", x86PackedArithmeticAdd},
		{"VPMULLQ", x86PackedArithmeticAdd | x86PackedArithmeticSubtract},
		{"PADDD", x86PackedArithmeticLowMultiply},
	} {
		t.Run(fmt.Sprintf("%s/families%d", row.op, row.families), func(t *testing.T) {
			spec, known := x86PackedArithmeticSpecForOp(row.op, row.families)
			if known || spec != (x86PackedArithmeticSpec{}) {
				t.Fatal("unrecognized family leaked another family's metadata", known, spec)
			}
			form, known, err := x86PackedArithmeticProperties(row.op, Instr{Op: row.op}, "amd64", row.families)
			if known || err != nil || form != (x86PackedArithmeticForm{}) {
				t.Fatal("unrecognized family began physical parsing", known, err, form)
			}
		})
	}
}

func TestX86PackedSubtractMetadataRetainsBareNameContract(t *testing.T) {
	for _, name := range []string{"", "VPADDB", "VPMULLQ", "vpsubd", "VPSUBD.BAD", "VPSUBD.Z", " VPSUBD"} {
		t.Run(name, func(t *testing.T) {
			bits, mode, vector, known := amd64PackedSubtractProperties(name)
			if known || bits != 0 || mode != 0 || vector {
				t.Fatal("bare-name query changed its unrecognized result", bits, mode, vector, known)
			}
		})
	}
	bits, mode, vector, known := amd64PackedSubtractProperties("VPSUBD")
	if !known || bits != 32 || mode != amd64PackedSubtractWrap || !vector {
		t.Fatal("original bare opcode was lost", bits, mode, vector, known)
	}
}

func TestX86PackedArithmeticDispatchKeepsExactSourceIdentity(t *testing.T) {
	for _, row := range []struct {
		op          Op
		instruction string
	}{
		{"VPADDD", "VPSUBQ Y0,Y1,Y2"},
		{"VPSUBD", "VPADDD Y0,Y1,Y2"},
		{"VPADDUSB", "VPADDB Y0,Y1,Y2"},
		{"PADDD", "PADDL X0,X1"},
		{"VPMULLD", "VPADDD Y0,Y1,Y2"},
	} {
		t.Run(string(row.op), func(t *testing.T) {
			ins := x86ScalarLaneInstruction(t, row.instruction)
			form, known, err := x86PackedArithmeticProperties(row.op, ins, "amd64", 0)
			if !known || err == nil || form != (x86PackedArithmeticForm{}) {
				t.Fatal("dispatch replaced the original source opcode", known, err, form)
			}
		})
	}
	// Case folding is still allowed; this establishes syntax only, not NUM.
	ins := x86ScalarLaneInstruction(t, "VPSUBD Y0,Y1,Y2")
	if _, known, err := x86PackedArithmeticProperties("vpsubd", ins, "amd64", 0); !known || err != nil {
		t.Fatal("case-equivalent original opcode was lost", known, err)
	}
}
