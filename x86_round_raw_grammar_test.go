package plan9asm

import (
	"reflect"
	"testing"
)

func TestX86RoundNormalizedRawMode32GrammarDoesNotGrantNUM(t *testing.T) {
	for _, instruction := range []string{"VROUNDSS $255,(AX),X1,X2", "VROUNDSD $255,X0,X1,X2"} {
		t.Run(instruction, func(t *testing.T) {
			code := x86OrderingHintGoBytes(t, "amd64", "TEXT original(SB),4,$0-0\n"+instruction+"\nRET\n")
			if len(code) < 2 || code[len(code)-1] != 0xc3 {
				t.Fatal("original Go ROUND lost its complete RET boundary")
			}
			source := "TEXT rawround(SB),4,$0-0\n" + x86DwordProductDirectives(code[:len(code)-1]) + "\nRET\n"
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			normalized, err := normalizeX86RawFile(file, "386")
			if err != nil || len(normalized.Funcs) != 1 || len(normalized.Funcs[0].Instrs) != 3 {
				t.Fatal("actual original bytes did not retain one physical ROUND", err)
			}
			ins := normalized.Funcs[0].Instrs[1]
			if ins.Op != x86ScalarLaneInstruction(t, instruction).Op || ins.x86Encoded || ins.x86SourceRaw == nil {
				t.Fatal("decoder's original raw metadata contract changed", ins.Op, ins.x86Encoded, ins.x86SourceRaw)
			}
			if form, known, err := x86RoundProperties(ins, "386"); !known || err != nil || form.immediate != 255 || !form.spec.scalar {
				t.Fatal("normalized physical mode32 ROUND was mistaken for an ordinary Go four-operand source", known, err)
			}
			for _, change := range []string{"original", "encoded-marker", "synthetic-raw-marker", "changed-source"} {
				changed := ins
				changed.Args = append([]Operand(nil), ins.Args...)
				switch change {
				case "encoded-marker":
					changed.x86Encoded = true
				case "synthetic-raw-marker":
					changed.x86SourceRaw = &x86SourceRawInstruction{op: ins.Op, args: append([]Operand(nil), ins.Args...)}
				case "changed-source":
					changed.Args[1] = Operand{Kind: OpReg, Reg: "X3"}
				}
				if _, known, err := x86RoundProperties(changed, "386"); !known || err != nil {
					t.Fatal("raw grammar boundary was replaced by NUM authority", change, known, err)
				}
				for _, native := range []bool{false, true} {
					state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
					state.pointerGP[0] = true
					for register := 0; register < 4; register++ {
						state.writeVector(register, 64, ^uint64(0), false)
					}
					before := state.clone()
					if accepted, known := x86ResultRoundStep(changed, &state, nil, "386", native); !known || accepted || !reflect.DeepEqual(before, state) {
						t.Fatal("raw or mutated raw ROUND borrowed native NUM/source permission", change, native)
					}
				}
			}
			ordinary := ins
			ordinary.x86SourceRaw = nil
			if _, known, err := x86RoundProperties(ordinary, "386"); !known || err == nil {
				t.Fatal("removing raw provenance admitted ordinary mode32 four-operand source")
			}
		})
	}
}
