package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86SqrtCallerInputAndAliasContract(t *testing.T) {
	for _, row := range x86SqrtInputRows("amd64") {
		if strings.Contains(row, "(AX)") {
			continue
		}
		t.Run(row, func(t *testing.T) {
			ins := x86ScalarLaneInstruction(t, row)
			for _, missing := range []string{"none", "input", "upper", "destination", "mask"} {
				state := x86SourceStackState{vectors: map[Reg]uint64{
					"Z0": ^uint64(0), "Z1": ^uint64(0), "Z2": ^uint64(0)}, masks: map[Reg]bool{"K1": true}}
				switch missing {
				case "input":
					state.vectors["Z0"] &^= 1
				case "upper":
					state.vectors["Z1"] = 0
				case "destination":
					state.vectors["Z2"] = 0
				case "mask":
					state.masks["K1"] = false
				}
				before, masks := x86CloneCallerVectorState(state.vectors, state.masks)
				want := missing != "input" && (missing != "mask" || !strings.Contains(row, "K1")) &&
					(missing != "destination" || !strings.Contains(row, "K1") || strings.Contains(row, ".Z"))
				accepted := x86CallerVectorMoveStep(&ins, &state, nil)
				if accepted != want || !reflect.DeepEqual(state.masks, masks) || !want && !reflect.DeepEqual(state.vectors, before) {
					t.Fatal("caller source or mask contract", missing, accepted, want)
				}
				if want && missing == "upper" && (strings.HasPrefix(row, "VSQRTSS") || strings.HasPrefix(row, "VSQRTSD")) {
					low := uint64(0xf)
					if strings.HasPrefix(row, "VSQRTSD") {
						low = 0xff
					}
					if state.vectors["Z2"] != ^uint64(0xffff)|low {
						t.Fatal("caller invented scalar passthrough bytes")
					}
				}
			}
		})
	}
}

func TestX86SqrtCallerCompleteSource(t *testing.T) {
	for _, op := range []string{"SQRTSS", "SQRTSD", "SQRTPS", "SQRTPD", "VSQRTSS", "VSQRTSD", "VSQRTPS", "VSQRTPD"} {
		t.Run(op, func(t *testing.T) {
			args := "X0,X2"
			if op == "VSQRTSS" || op == "VSQRTSD" {
				args = "X0,X1,X2"
			}
			body := fmt.Sprintf("MOVQ (CX),AX\nCMPQ AX,$4\nJL short\nVMOVUPS (DI),X0\nVPXORD Z1,Z1,Z1\n%s %s\nMOVSS X2,(DX)\nJMP done\nshort:\nMOVL $0,(DX)\ndone:\n", op, args)
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
				t.Fatal("complete source-bound sqrt caller rejected", err)
			}
		})
	}
}

func TestX86SqrtMemoryShapesAndCallerBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86SqrtInputRows(arch) {
			if !strings.Contains(row, "(AX)") {
				continue
			}
			t.Run(arch+"/"+row, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row)
				want := int64(16)
				if strings.HasSuffix(row, "Y2") {
					want = 32
				} else if strings.HasSuffix(row, "Z2") {
					want = 64
				}
				op := strings.Fields(row)[0]
				if strings.HasPrefix(op, "SQRTSS") || strings.HasPrefix(op, "VSQRTSS") || strings.Contains(op, "BCST") {
					want = 4
					if strings.HasPrefix(op, "VSQRTPD") {
						want = 8
					}
				} else if strings.HasPrefix(op, "SQRTSD") || strings.HasPrefix(op, "VSQRTSD") {
					want = 8
				}
				for index := -1; index <= len(ins.Args); index++ {
					width, write, valid := x86InstructionMemoryShape(ins, index, arch)
					if valid != (index == 0) || valid && (width != want || write) {
						t.Fatal("source tuple differs", index, width, write, valid, want)
					}
				}
				// Numerical and mask inputs do not supply caller pointer backing.
				state := x86SourceStackState{vectors: map[Reg]uint64{"Z0": ^uint64(0), "Z1": ^uint64(0), "Z2": ^uint64(0)}, masks: map[Reg]bool{"K1": true}}
				if x86CallerVectorMoveStep(&ins, &state, &x86GoCallerRegionProof{}) {
					t.Fatal("sqrt invented a caller-memory region")
				}
			})
		}
	}
}
