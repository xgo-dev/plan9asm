package plan9asm

import (
	"fmt"
	"testing"
)

func TestX86X87IntegerRoundCompleteTypedRows(t *testing.T) {
	// Independent nine Go encoder directions, not derived from the effect map.
	rows := []struct {
		op         string
		width      int64
		load, push bool
		pop        uint8
	}{
		{"FMOVW", 2, true, true, 0}, {"FMOVW", 2, false, false, 0},
		{"FMOVWP", 2, false, false, 1},
		{"FMOVL", 4, true, true, 0}, {"FMOVL", 4, false, false, 0},
		{"FMOVLP", 4, false, false, 1},
		{"FMOVV", 8, true, true, 0}, {"FMOVVP", 8, false, false, 1},
		{"FRNDINT", 0, false, false, 0},
	}
	for _, arch := range []string{"386", "amd64"} {
		for rowIndex, row := range rows {
			memory := []string{"(AX)", "-7(BX)(CX*4)", "value+0(FP)", "local-8(SP)", "·value(SB)"}
			if row.width == 0 {
				memory = []string{""}
			}
			for _, operand := range memory {
				source := row.op
				index := 1
				if row.width != 0 {
					if row.load {
						source += " " + operand + ",F0"
						index = 0
					} else {
						source += " F0," + operand
					}
				}
				t.Run(fmt.Sprintf("%s/row%d/%s", arch, rowIndex, source), func(t *testing.T) {
					ins := x86X87ValueInstruction(t, source)
					form, known, err := x86X87ValueProperties(ins, arch)
					if !known || err != nil || form.memoryBytes() != row.width || form.push != row.push || form.spec.pop != row.pop {
						t.Fatal("complete integer/round direction lost its width, push or pop", known, err, form)
					}
					if operand == "value+0(FP)" {
						width, write, known := X86FPAccessBytes(ins, index, arch)
						if !known || width != row.width || write == row.load {
							t.Fatal("FP observation diverged from the complete typed row", width, write, known)
						}
					}
				})
			}
		}
		for _, source := range []string{
			"FMOVW value+0(FP),F1", "FMOVW F1,value+0(FP)", "FMOVW F0,F1",
			"FMOVL value+0(FP),F1", "FMOVL F1,value+0(FP)", "FMOVL F0,F1",
			"FMOVV F0,value+0(FP)", "FMOVVP value+0(FP),F0",
			"FMOVWP value+0(FP),F0", "FMOVLP value+0(FP),F0",
			"FMOVW $1,F0", "FMOVL $(1.0),F0", "FMOVV AX,F0",
			"FRNDINT F0", "FMOVWP", "FMOVV.Z value+0(FP),F0",
		} {
			t.Run(arch+"/invalid/"+source, func(t *testing.T) {
				ins := x86X87ValueInstruction(t, source)
				if _, known, err := x86X87ValueProperties(ins, arch); !known || err == nil {
					t.Fatal("malformed/nonexistent integer row was accepted", known, err)
				}
				for index := range ins.Args {
					if width, _, known := X86FPAccessBytes(ins, index, arch); known || width != 0 {
						t.Fatal("rejected integer row leaked a width observation", width, known)
					}
				}
			})
		}
	}
}

func TestX86X87IntegerRoundWholeResultObligationHasNoStoreProbe(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, source := range []string{
			"FMOVW input+0(FP),F0", "FMOVW F0,input+0(FP)", "FMOVWP F0,input+0(FP)",
			"FMOVL input+0(FP),F0", "FMOVL F0,input+0(FP)", "FMOVLP F0,input+0(FP)",
			"FMOVV input+0(FP),F0", "FMOVVP F0,input+0(FP)", "FRNDINT",
		} {
			t.Run(arch+"/"+source, func(t *testing.T) {
				_, file, sig, _ := x86ResultInitializationFixture(t, arch, "func Value(input uint64) uint64", source+"\nRET")
				if !x86TypedFPResultNeedsProof(file.Funcs[0], sig, arch) {
					t.Fatal("integer/round family evaded its result obligation without a result store")
				}
			})
		}
	}
}
