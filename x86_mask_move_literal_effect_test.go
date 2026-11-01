package plan9asm

import (
	"fmt"
	"reflect"
	"testing"
)

func TestX86MaskMoveLiteralProofExactReadWriteRoles(t *testing.T) {
	forms := []struct {
		operands        string
		gpRead, gpWrite bool
	}{
		{"AX,K1", true, false}, {"K1,K7", false, false}, {"K1,BX", false, true},
		{"(DX),K1", false, false}, {"K1,(DX)", false, false},
	}
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86ResultMaskMoveWidthOracle {
			for _, form := range forms {
				t.Run(arch+"/"+row.op+"/"+form.operands, func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, row.op+" "+form.operands)
					effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
					width := int64(row.bits / 8)
					if (form.gpRead || form.gpWrite) && width > x86ResultPointerWord(arch) {
						width = x86ResultPointerWord(arch) // GP WIG; K/memory retain native width.
					}
					writeWidth := width
					if form.gpWrite && writeWidth < x86ResultPointerWord(arch) {
						writeWidth = x86ResultPointerWord(arch)
					}
					want := x86TypedByteEffect{requiresResultProof: true, operands: []x86TypedByteOperand{
						{index: 0, operand: ins.Args[0], width: width, read: true},
						{index: 1, operand: ins.Args[1], width: writeWidth, write: true},
					}}
					if !known || err != nil || !reflect.DeepEqual(effect, want) {
						t.Fatal("mask move lost exact data width, destination zeroing or preserved FLAGS", effect, known, err)
					}
					state := x86SDKLiteralState{comparison: 1, constant: 16, compared: true}
					state.gp[0] = x86SDKLiteralUnknownNumber(x86ResultPointerWord(arch))
					state.gp[1] = x86SDKLiteralValue{width: x86ResultPointerWord(arch), minimum: 0, maximum: 15}
					state.gp[3] = x86SDKLiteralValue{symbol: "table<>", minimum: 0, maximum: 0}
					wantState := state
					if form.gpWrite {
						wantState.gp[3] = x86SDKLiteralValue{}
					}
					if err := x86SDKLiteralTransfer(ins, &state, FuncSig{}, arch, nil); err != nil || !reflect.DeepEqual(state, wantState) {
						t.Fatal("mask move changed unrelated range, retained overwritten literal or invented memory facts", state, err)
					}
				})
			}
		}
	}
}

func TestX86MaskMoveLiteralCannotEscapeOrPreserveOverwrittenRange(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86ResultMaskMoveWidthOracle {
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				state := x86SDKLiteralState{}
				state.gp[0] = x86SDKLiteralValue{symbol: "table<>"}
				ins := x86ScalarLaneInstruction(t, fmt.Sprintf("%s AX,K1", row.op))
				if err := x86SDKLiteralTransfer(ins, &state, FuncSig{}, arch, nil); err == nil {
					t.Fatal("literal address escaped as mask data")
				}
				state = x86SDKLiteralState{comparison: 1, constant: 16, compared: true}
				state.gp[1] = x86SDKLiteralValue{width: x86ResultPointerWord(arch), maximum: 15}
				ins = x86ScalarLaneInstruction(t, row.op+" K1,CX")
				if err := x86SDKLiteralTransfer(ins, &state, FuncSig{}, arch, nil); err != nil ||
					state.compared || state.gp[1] != (x86SDKLiteralValue{}) {
					t.Fatal("mask destination borrowed the previous index envelope", state, err)
				}
			})
		}
	}
}
