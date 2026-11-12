package plan9asm

import (
	"fmt"
	"testing"
)

func TestARM64CodeAddressTransformsRetainSourceDerivedProvenance(t *testing.T) {
	inputs := []struct {
		name  string
		value arm64ControlValue
	}{
		{"pure", arm64ControlFromMap(map[string]bool{"label:caller": true})},
		{"joined_unknown", arm64ControlFromMap(map[string]bool{"label:caller": true, "": true})},
		{"already_derived", arm64ControlFromMap(map[string]bool{"label:caller": true, "code-derived:": true, "": true})},
	}
	for _, form := range []struct {
		name, instruction string
		transforms        bool
	}{
		{"move", "MOVD R10,R11", false},
		{"add_zero", "ADD $0,R10,R11", false},
		{"sub_zero", "SUB $0,R10,R11", false},
		{"add_positive", "ADD $4,R10,R11", true},
		{"add_negative", "ADD $-4,R10,R11", true},
		{"sub_positive", "SUB $4,R10,R11", true},
		{"sub_negative", "SUB $-4,R10,R11", true},
		{"address_positive", "MOVD $4(R10),R11", true},
		{"address_negative", "MOVD $-4(R10),R11", true},
		{"dynamic_add", "ADD R12,R10,R11", true},
		{"dynamic_sub", "SUB R12,R10,R11", true},
		{"xor", "EOR $4,R10,R11", true},
		{"or", "ORR $4,R10,R11", true},
		{"and", "AND $-16,R10,R11", true},
		{"shift_left", "LSL $2,R10,R11", true},
		{"shift_right", "LSR $2,R10,R11", true},
		{"arithmetic_shift", "ASR $2,R10,R11", true},
		{"rotate", "ROR $2,R10,R11", true},
		{"signed_narrow", "MOVW R10,R11", true},
		{"unsigned_narrow", "MOVWU R10,R11", true},
		{"negate", "NEG R10,R11", true},
		{"reverse", "REV R10,R11", true},
	} {
		t.Run(form.name, func(t *testing.T) {
			source := fmt.Sprintf("TEXT provenance(SB),4,$16-0\n%s\nRET\n", form.instruction)
			requireARM64GoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			for _, input := range inputs {
				t.Run(input.name, func(t *testing.T) {
					caller := arm64ControlFromMap(map[string]bool{"label:caller": true})
					state := &arm64ControlState{
						unexposedSP: true,
						regs: map[Reg]arm64ControlValue{
							SP: arm64ControlFromMap(map[string]bool{"sp:0": true}), "R9": arm64ControlExternal(),
							"R10": input.value, "R12": arm64ControlExternal(),
						},
						memory: map[string]arm64ControlValue{"sp:0": caller},
					}
					state.transfer(ins, arm64ControlOp(ins), false, nil)
					value := state.regs["R11"]
					derived := form.transforms || arm64ControlHas(input.value, "code-derived:")
					if arm64ControlHas(value, "code-derived:") != derived || !arm64ControlHas(value, "label:caller") {
						t.Fatalf("source transform lost code provenance: instruction=%q, input=%v, output=%v", form.instruction, input.value, value)
					}
					state.write(Operand{Kind: OpMem, Mem: MemRef{Base: "R9"}}, value, false)
					intact := arm64ControlEqual(state.source(Operand{Kind: OpMem, Mem: MemRef{Base: SP}}, false), caller)
					if intact == derived {
						t.Fatalf("derived=%t must control saved-LR uncertainty, memory=%v, escaped=%v", derived, state.memory, state.escaped)
					}
				})
			}
		})
	}
}

func TestARM64CodeAddressOffsetRetainsProvenanceAcrossUnknownJoins(t *testing.T) {
	for _, input := range []arm64ControlValue{
		arm64ControlFromMap(map[string]bool{"label:caller": true}),
		arm64ControlFromMap(map[string]bool{"label:caller": true, "": true}),
		arm64ControlFromMap(map[string]bool{"code-derived:": true, "": true}),
	} {
		for _, offset := range []int64{-1 << 63, -4, 4, 1<<63 - 1} {
			t.Run(fmt.Sprintf("%v/%d", input, offset), func(t *testing.T) {
				value := arm64ControlOffset(input, offset)
				if !arm64ControlHas(value, "code-derived:") || !arm64ControlHas(value, "") {
					t.Fatalf("native-PC offset became ordinary unknown data: %v", value)
				}
				state := &arm64ControlState{
					regs:   map[Reg]arm64ControlValue{"R10": value},
					memory: map[string]arm64ControlValue{"fp:0": value},
				}
				state.merge(&arm64ControlState{
					regs:   map[Reg]arm64ControlValue{"R10": arm64ControlExternal()},
					memory: map[string]arm64ControlValue{},
				})
				for location, joined := range map[string]arm64ControlValue{
					"register": state.regs["R10"], "memory": state.memory["fp:0"],
				} {
					if !arm64ControlHas(arm64ControlLabels(joined), "code-derived:") || !arm64ControlHas(arm64ControlAddressTaint(joined), "code-derived:") {
						t.Errorf("%s filtering washed away a source-derived PC: %v", location, joined)
					}
				}
			})
		}
	}
}
