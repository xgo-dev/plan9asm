package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Keep this inventory independent of implementation maps and operand parsers.
func x86ConflictFunnelRows() []struct {
	op       string
	bits     int
	unary    bool
	variable bool
} {
	return []struct {
		op       string
		bits     int
		unary    bool
		variable bool
	}{
		{"VPCONFLICTD", 32, true, false},
		{"VPCONFLICTQ", 64, true, false},
		{"VPSHLDW", 16, false, false},
		{"VPSHLDD", 32, false, false},
		{"VPSHLDQ", 64, false, false},
		{"VPSHRDW", 16, false, false},
		{"VPSHRDD", 32, false, false},
		{"VPSHRDQ", 64, false, false},
		{"VPSHLDVW", 16, false, true},
		{"VPSHLDVD", 32, false, true},
		{"VPSHLDVQ", 64, false, true},
		{"VPSHRDVW", 16, false, true},
		{"VPSHRDVD", 32, false, true},
		{"VPSHRDVQ", 64, false, true},
	}
}

func x86ConflictFunnelInstruction(op, bank, first, mask string, unary, variable bool) string {
	arguments := first + ","
	if !unary {
		arguments += bank + "1,"
		if !variable {
			arguments = "$255," + arguments
		}
	}
	return op + " " + arguments + mask + bank + "2"
}

func TestX86ConflictFunnelEveryInputByteAndIndependentState(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86ConflictFunnelRows() {
			if arch == "386" && !row.unary && !row.variable {
				continue // Stock Go's named frontend has a three-operand limit.
			}
			for _, bank := range []string{"X", "Y", "Z"} {
				for _, mode := range []string{"plain", "merge", "zero"} {
					if arch == "386" && !row.unary && mode != "plain" {
						continue
					}
					t.Run(arch+"/"+row.op+"/"+bank+"/"+mode, func(t *testing.T) {
						op, mask := row.op, ""
						if mode != "plain" {
							mask = "K1,"
						}
						if mode == "zero" {
							op += ".Z"
						}
						ins := x86ScalarLaneInstruction(t, x86ConflictFunnelInstruction(op, bank, bank+"0", mask, row.unary, row.variable))
						width := amd64VectorByteWidth(Reg(bank + "0"))
						inputs := []int{0}
						if !row.unary {
							inputs = append(inputs, 1)
						}
						if row.variable || mode == "merge" {
							inputs = append(inputs, 2)
						}
						for _, input := range inputs {
							for missing := -1; missing < width; missing++ {
								state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
								for register := 0; register < 3; register++ {
									state.writeVector(register, 64, ^uint64(0), false)
								}
								state.masks[1], state.pointerGP[3], state.gp[1] = true, true, 0x55
								if missing >= 0 {
									state.writeVector(input, 64, state.vectorBytes(input)&^(uint64(1)<<uint(missing)), false)
								}
								want := state.clone()
								if missing < 0 {
									want.writeVector(2, width, x86CallerVectorByteMask(int64(width)), false)
								}
								accepted := x86ResultTransfer(ins, &state, nil, 0, arch)
								if accepted != (missing < 0) || !reflect.DeepEqual(state, want) {
									t.Fatal("complete numerical inputs, upper aliases or independent state changed", input, missing, accepted)
								}
							}
						}
					})
				}
			}
		}
	}
}

func x86ConflictFunnelInputObjects(t *testing.T, bank string) {
	t.Helper()
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, move := goWordSize(target.arch), "MOVQ"
			if word == 4 {
				move = "MOVL"
			}
			var source, declarations strings.Builder
			count, batches, inBatch := 0, 0, 0
			flush := func() {
				if inBatch == 0 || inBatch > 64 {
					t.Fatal("invalid bounded family batch", inBatch)
				}
				t.Run(fmt.Sprintf("batch%02d", batches), func(t *testing.T) {
					x86RawNumericalFamilyObjects(t, source.String(), declarations.String(), target.arch, target.triple)
				})
				batches++
				inBatch = 0
				source.Reset()
				declarations.Reset()
			}
			for _, row := range x86ConflictFunnelRows() {
				if target.arch == "386" && !row.unary && !row.variable {
					continue
				}
				for _, mode := range []string{"plain", "merge", "zero"} {
					if target.arch == "386" && !row.unary && mode != "plain" {
						continue
					}
					inputs := []string{bank + "0", "(SI)"}
					if row.bits != 16 {
						inputs = append(inputs, "broadcast")
					}
					for _, input := range inputs {
						op, mask, operand := row.op, "", input
						if input == "broadcast" {
							op, operand = op+".BCST", "(SI)"
						}
						if mode != "plain" {
							mask = "K1,"
						}
						if mode == "zero" {
							op += ".Z"
						}
						instruction := x86ConflictFunnelInstruction(op, bank, operand, mask, row.unary, row.variable)
						name := fmt.Sprint("Value", count)
						fmt.Fprintf(&declarations, "func %s(out,a,b,old *[64]byte)\n", name)
						fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),DI\n"+
							"%s a+%d(FP),SI\n%s b+%d(FP),BX\n%s old+%d(FP),CX\n"+
							"VMOVUPS (SI),Z0\nVMOVUPS (BX),Z1\nVMOVUPS (CX),Z2\n"+
							"MOVL $-1431655766,AX\nKMOVD AX,K1\nSTC\n%s\nVMOVUPS Z2,(DI)\nRET\n",
							name, 4*word, move, move, word, move, 2*word, move, 3*word, instruction)
						count++
						inBatch++
						if inBatch == 64 {
							flush()
						}
					}
				}
			}
			want := 114
			if target.arch == "386" {
				want = 34
			}
			if count != want {
				t.Fatal("independent complete family/memory/mask inventory changed", count, want)
			}
			if inBatch != 0 {
				flush()
			}
			if batches != (want+63)/64 {
				t.Fatal("incomplete family batch union", batches)
			}
		})
	}
}

func TestX86ConflictFunnelCompleteXInputObjects(t *testing.T) {
	x86ConflictFunnelInputObjects(t, "X")
}

func TestX86ConflictFunnelCompleteYInputObjects(t *testing.T) {
	x86ConflictFunnelInputObjects(t, "Y")
}

func TestX86ConflictFunnelCompleteZInputObjects(t *testing.T) {
	x86ConflictFunnelInputObjects(t, "Z")
}

func TestX86ConflictFunnelVoidAndUnusedBoolNeedActualInputs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range x86ConflictFunnelRows() {
			if target.arch == "386" && !row.unary && !row.variable {
				continue
			}
			for _, declaration := range []string{"func Value()", "func Value(unused bool)"} {
				instruction := x86ConflictFunnelInstruction(row.op, "X", "X0", "", row.unary, row.variable)
				source := "TEXT ·Value(SB),4,$0\n" + instruction + "\nRET\n"
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("dead result silently acquired numerical input bytes", target, row.op, declaration, api, err)
					}
				}
			}
		}
	}
}
