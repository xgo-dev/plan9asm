package plan9asm

import (
	"errors"
	"reflect"
	"testing"
)

var x86PackedArithmeticQuerySink x86LegacyIntegerArithmeticForm

func TestX86LegacyIntegerArithmeticQueryIsReadOnlyAndBounded(t *testing.T) {
	rows := []struct {
		instruction string
		source      Reg
		allocations float64
	}{
		{"PADDQ X0,X1", "X0", 0},
		{"PSUBL X0,X1", "X0", 0},
		{"PADDB X0,X1", "X0", 1},
	}
	for _, bank := range []struct{ input, physical Reg }{
		{AX, "M0"}, {CX, "M1"}, {DX, "M2"}, {BX, "M3"},
		{SP, "M4"}, {BP, "M5"}, {SI, "M6"}, {DI, "M7"},
		{"R8", "M0"}, {"R9", "M1"}, {"R10", "M2"}, {"R11", "M3"},
		{"R12", "M4"}, {"R13", "M5"}, {"R14", "M6"}, {"R15", "M7"},
	} {
		rows = append(rows, struct {
			instruction string
			source      Reg
			allocations float64
		}{"PADDB " + string(bank.input) + ",M1", bank.physical, 1})
	}
	for _, row := range rows {
		t.Run(row.instruction, func(t *testing.T) {
			ins := x86ScalarLaneInstruction(t, row.instruction)
			before := ins
			before.Args = append([]Operand(nil), ins.Args...)
			var known bool
			var err error
			allocations := testing.AllocsPerRun(100, func() {
				x86PackedArithmeticQuerySink, known, err = x86LegacyIntegerArithmeticProperties(ins.Op, ins, "amd64")
			})
			if !known || err != nil || x86PackedArithmeticQuerySink.source.Reg != row.source {
				t.Fatal("query lost the original physical bank", known, err, x86PackedArithmeticQuerySink.source)
			}
			if !reflect.DeepEqual(ins, before) {
				t.Fatal("read-only shape query changed its original input")
			}
			if x86PackedArithmeticQuerySink.mmx && !errors.Is(x86LegacyIntegerArithmeticEmitterContext(x86PackedArithmeticQuerySink, ins), ErrProbeNeedsContext) {
				t.Fatal("physical bank projection acquired emitter permission")
			}
			if allocations > row.allocations {
				t.Errorf("shape query allocates %.0f times; at most %.0f physical projections needed", allocations, row.allocations)
			}
		})
	}
}
