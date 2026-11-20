package plan9asm

import (
	"fmt"
	"testing"
)

func TestX86X87ConditionalValueWholeGoRegisterGrammar(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range x87ConditionalMoveGo127Ops {
			for _, row := range []struct {
				operands string
				good     bool
			}{
				{"F0,F0", true}, {"F7,F0", true}, {"F8,F0", false},
				{"F1,F2", false}, {"0(AX),F0", false}, {"F1", false},
			} {
				t.Run(arch+"/"+op+"/"+row.operands, func(t *testing.T) {
					_, known, err := x86X87ValueProperties(x86X87ValueInstruction(t, op+" "+row.operands), arch)
					if !known || (err == nil) != row.good {
						t.Fatal("conditional value grammar differs from the complete yfcmv register row", known, err)
					}
				})
			}
		}
	}
}

func TestX86X87ConditionalValueNeedsFlagsAndBothReachingValues(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range []struct {
			op    string
			flags uint8
		}{
			{"FCMOVB", x86ByteFlagCF}, {"FCMOVCS", x86ByteFlagCF},
			{"FCMOVNB", x86ByteFlagCF}, {"FCMOVCC", x86ByteFlagCF},
			{"FCMOVBE", x86ByteFlagCF | x86ByteFlagZF}, {"FCMOVLS", x86ByteFlagCF | x86ByteFlagZF},
			{"FCMOVNBE", x86ByteFlagCF | x86ByteFlagZF}, {"FCMOVHI", x86ByteFlagCF | x86ByteFlagZF},
			{"FCMOVE", x86ByteFlagZF}, {"FCMOVEQ", x86ByteFlagZF}, {"FCMOVNE", x86ByteFlagZF},
			{"FCMOVNU", x86ByteFlagPF}, {"FCMOVU", x86ByteFlagPF}, {"FCMOVUN", x86ByteFlagPF},
		} {
			for _, mutation := range []string{"none", "missing-flags", "unknown-source", "unknown-destination", "unknown-stack"} {
				t.Run(fmt.Sprintf("%s/%s/%s", arch, row.op, mutation), func(t *testing.T) {
					state := x86ResultState{flags: row.flags, x87: &x86ResultX87State{slots: 3, depth: 2, integer: [8]uint8{4, 8}}}
					switch mutation {
					case "missing-flags":
						state.flags = 0
					case "unknown-source":
						state.x87.slots &^= 2
					case "unknown-destination":
						state.x87.slots &^= 1
					case "unknown-stack":
						state.x87.invalid = true
					}
					before := state.clone()
					accepted, known := x86ResultX87ValueStep(x86X87ValueInstruction(t, row.op+" F1,F0"), &state, nil, 0, arch)
					if !known || accepted != (mutation == "none") {
						t.Fatal("conditional value used missing FLAGS/source/destination/shape", accepted, known)
					}
					if accepted && (state.x87.integer != [8]uint8{8, 8} || state.x87.slots != 3 || state.x87.depth != 2 ||
						state.flags != before.flags || state.gp != before.gp) {
						t.Fatal("conditional result did not join precisely the two source ranges or changed unrelated state")
					}
				})
			}
		}
	}
}
