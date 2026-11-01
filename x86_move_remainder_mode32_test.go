package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// These families have different existing contracts. Scalar grammar is not a
// physical-bank certificate; its NUM domain refuses high banks even when all
// candidate bytes/masks/native-address roles are supplied independently.
func x86OfficialMoveRemainderMode32InstructionBoundary(t *testing.T, row string, w goasmrules.X86PackedBinaryWitness) string {
	t.Helper()
	ins := x86ScalarLaneInstruction(t, w.Instruction)
	var output strings.Builder
	context := newX86Ctx(&output, Func{}, FuncSig{Ret: Void}, nil, nil, "386", "i386-unknown-linux-gnu", false)
	table := strings.Split(row, "/")[3]
	if table == "_yvmovsd" {
		form, known, err := amd64ScalarVectorMoveProperties(ins, "386")
		if !known {
			t.Fatal("scalar source lost its independent typed grammar", row)
		}
		if len(ins.Args) == 4 {
			if err == nil {
				t.Fatal("named Go386 four-operand grammar unexpectedly accepted", row)
			}
			if known, _, err := context.lowerVectorScalarMove(ins.Op, ins); !known || err == nil || output.Len() != 0 {
				t.Fatal("rejected scalar arity emitted IR", row, known, err, output.String())
			}
			return "grammar"
		}
		if err != nil {
			t.Fatal("actual Go scalar grammar was broadened or narrowed", row, err)
		}
		state := x86ResultState{flags: x86ByteFlagsAll}
		for index := 0; index < 32; index++ {
			state.writeVector(index, 64, ^uint64(0), false)
		}
		for index := range state.masks {
			state.masks[index] = true
		}
		state.pointerGP[0] = true
		low := ins
		low.Args = append([]Operand(nil), ins.Args...)
		for index, arg := range low.Args {
			if register, valid := amd64ParseXReg(arg.Reg); arg.Kind == OpReg && valid && register >= 16 {
				low.Args[index].Reg = Reg(fmt.Sprint("X", register-16))
			}
		}
		lowForm, known, err := amd64ScalarVectorMoveProperties(low, "386")
		control := state.clone()
		if !known || err != nil || !x86ScalarVectorMoveResultTransfer(low, lowForm, &control, nil, 0, "386", true) {
			t.Fatal("paired defined low-bank NUM control failed; high rejection is not isolated", row, err)
		}
		before := state.clone()
		if x86ScalarVectorMoveResultTransfer(ins, form, &state, nil, 0, "386", true) || !reflect.DeepEqual(before, state) {
			t.Fatal("fully defined high scalar bytes bypassed NUM physical-bank refusal", row)
		}
		return "NUM"
	}
	if table == "_yvmovntdq" || table == "_yvmovntdqa" {
		form, known, err := x86NonTemporalVectorProperties(ins.Op, ins, "386")
		if !known {
			t.Fatal("non-temporal source lost its typed grammar", row)
		}
		if w.Width == 512 {
			if err == nil {
				t.Fatal("Go386 high Z-bank grammar was broadened", row)
			}
			if known, _, err := context.lowerNonTemporalVectorMove(ins.Op, ins); !known || err == nil || output.Len() != 0 {
				t.Fatal("rejected non-temporal Z grammar emitted IR", row, err, output.String())
			}
			return "grammar"
		}
		if err != nil || !form.move.ordinaryMemory(ins, "386") {
			t.Fatal("non-temporal mode control lacks ordinary native memory", row, err)
		}
		known, _, err = context.lowerNonTemporalVectorMove(ins.Op, ins)
		if !known || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "physical mode32 binding") || output.Len() != 0 {
			t.Fatal("matching-target non-temporal mode guard emitted or borrowed earlier rejection", row, err, output.String())
		}
		return "mode"
	}
	_, known, err := x86TypedInstructionByteEffect(ins.Op, ins, "386")
	if !known {
		_, known, err = x86GPSIMDTransferProperties(ins, "386")
	}
	if !known || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "physical mode32 binding") {
		t.Fatal("half/GP transfer lost its direct typed mode guard", row, known, err)
	}
	if _, err := context.lowerInstr(-1, 0, ins, nil, nil); !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "physical mode32 binding") || output.Len() != 0 {
		t.Fatal("half/GP transfer emitted or borrowed non-mode rejection", row, err, output.String())
	}
	return "mode"
}
