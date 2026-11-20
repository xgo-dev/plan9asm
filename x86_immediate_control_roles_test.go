package plan9asm

import (
	"fmt"
	"testing"
)

func TestX86ImmediateControlHelpersRetainIntegerBoundaries(t *testing.T) {
	for bits := 1; bits < 63; bits++ {
		unsigned, signed := int64(1)<<bits, int64(1)<<(bits-1)
		for _, value := range []int64{-signed - 1, -signed, -1, 0, signed - 1, signed, unsigned - 1, unsigned} {
			operand := Operand{Kind: OpImm, Imm: value}
			if amd64UnsignedImmediate(operand, bits) != (value >= 0 && value < unsigned) ||
				amd64SignedImmediate(operand, bits) != (value >= -signed && value < signed) {
				t.Fatal("integer control boundary changed", bits, value)
			}
		}
	}
	for _, value := range []int64{-129, -128, -1, 0, 127, 128, 255, 256} {
		if amd64VectorByteShiftImmediate(Operand{Kind: OpImm, Imm: value}) != (value >= -128 && value <= 255) {
			t.Fatal("encoded byte control boundary changed", value)
		}
	}
}

func TestX86ImmediateControlHelpersRejectNonIntegerRoles(t *testing.T) {
	for name, check := range map[string]func(Operand) bool{
		"unsigned": func(operand Operand) bool { return amd64UnsignedImmediate(operand, 8) },
		"signed":   func(operand Operand) bool { return amd64SignedImmediate(operand, 8) },
		"byte":     amd64VectorByteShiftImmediate,
	} {
		t.Run(name, func(t *testing.T) {
			for _, operand := range []Operand{
				{Kind: OpImm, Imm: 0, ImmIsFloat: true},
				{Kind: OpImm, Imm: 0, ImmRaw: "UNRESOLVED"},
				{Kind: OpReg, Reg: AX},
				{Kind: OpSym, Sym: "control(SB)"},
			} {
				if check(operand) {
					t.Errorf("control invented a resolved integer from another operand role: %#v", operand)
				}
			}
		})
	}
}

func TestX86GFNIImmediateFloatZeroRejectedLikeGo(t *testing.T) {
	for _, op := range []string{"VGF2P8AFFINEQB", "VGF2P8AFFINEINVQB"} {
		t.Run(op, func(t *testing.T) {
			instruction := op + " $0.0,Z0,Z1,Z2"
			goAssemblerOracleOutput(t, "amd64", "TEXT ·Value(SB),4,$0-0\n"+instruction+"\nRET\n", "", false)
			ins := x86ScalarLaneInstruction(t, instruction)
			if _, known, err := x86GFNIProperties(ins.Op, ins, "amd64"); !known || err == nil {
				t.Fatal("GFNI FLOAT zero became Yu8", err)
			}
			positive := x86ScalarLaneInstruction(t, fmt.Sprintf("%s $0,Z0,Z1,Z2", op))
			if _, known, err := x86GFNIProperties(positive.Op, positive, "amd64"); !known || err != nil {
				t.Fatal("integer-zero control lost its original format", err)
			}
		})
	}
}
