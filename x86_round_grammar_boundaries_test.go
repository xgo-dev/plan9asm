package plan9asm

import (
	"fmt"
	"testing"
)

func TestX86RoundGoImmediateAndModeBoundary(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"VROUNDSS", "VROUNDSD"} {
			for _, immediate := range []int{-129, -128, -1, 0, 255, 256} {
				for _, physical := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/%d/encoded-%t", arch, op, immediate, physical), func(t *testing.T) {
						ins := x86ScalarLaneInstruction(t, fmt.Sprintf("%s $%d,X0,X1,X2", op, immediate))
						ins.x86Encoded = physical
						form, known, err := x86RoundProperties(ins, arch)
						want := immediate >= 0 && immediate <= 255 && (arch != "386" || physical)
						if !known || (err == nil) != want {
							t.Fatal("scalar ROUND confused Go Yu8/front-end arity with normalized physical encoding", known, err, want)
						}
						if want && form.immediate != uint8(immediate) {
							t.Fatal("ROUND immediate changed", form.immediate, immediate)
						}
					})
				}
			}
		}
		for _, op := range []string{"VROUNDPS", "VROUNDPD", "ROUNDPS", "ROUNDPD", "ROUNDSS", "ROUNDSD"} {
			for _, immediate := range []int{-129, -128, -1, 0, 255, 256} {
				t.Run(fmt.Sprintf("%s/%s/%d", arch, op, immediate), func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, fmt.Sprintf("%s $%d,X0,X1", op, immediate))
					_, known, err := x86RoundProperties(ins, arch)
					low := 0
					if op == "VROUNDPS" || op == "VROUNDPD" {
						low = -128
					}
					want := immediate >= low && immediate <= 255
					if !known || (err == nil) != want {
						t.Fatal("packed VEX Yi8/Yu8 or legacy Yu8 boundary changed", known, err, want)
					}
				})
			}
		}
	}
}

func TestX86RoundImmediateLiteralKinds(t *testing.T) {
	for _, row := range []string{"VROUNDSS $0,X0,X1,X2", "VROUNDSD $0,X0,X1,X2", "VROUNDPS $0,X0,X1", "ROUNDSS $0,X0,X1"} {
		for _, mutation := range []string{"floating", "unresolved", "non-immediate"} {
			t.Run(row+"/"+mutation, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row)
				switch mutation {
				case "floating":
					ins.Args[0].ImmIsFloat = true
				case "unresolved":
					ins.Args[0].ImmRaw = "$unresolved_round_control"
				case "non-immediate":
					ins.Args[0].Kind = OpReg
					ins.Args[0].Reg = AX
				}
				if _, known, err := x86RoundProperties(ins, "amd64"); !known || err == nil {
					t.Fatal("non-integer ROUND control silently became zero", mutation, known, err)
				}
			})
		}
	}
}
