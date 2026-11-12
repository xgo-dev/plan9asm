package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Independent of production: legacy yxm and both complete _yvaddsd rows.
// EVEX SS->SD has SAE only, whereas SD->SS has all four ER controls.
type x86ScalarPrecisionOracleRow struct {
	op, control, mode, source string
	input, output             int
	vector, high              bool
}

func x86ScalarPrecisionOracleRows(arch string) []x86ScalarPrecisionOracleRow {
	var rows []x86ScalarPrecisionOracleRow
	for _, scalar := range []struct {
		op            string
		input, output int
	}{{"CVTSS2SD", 4, 8}, {"CVTSD2SS", 8, 4}} {
		for _, source := range []string{"register", "native", "FP"} {
			rows = append(rows, x86ScalarPrecisionOracleRow{op: scalar.op, input: scalar.input, output: scalar.output, source: source})
		}
		controls := []string{"", "SAE"}
		if scalar.input == 8 {
			controls = []string{"", "RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"}
		}
		for _, mode := range []string{"plain", "merge", "zero"} {
			if arch == "386" && mode != "plain" {
				continue // Go's named frontend has no four-operand mode32 row.
			}
			for _, source := range []string{"register", "native", "FP"} {
				for _, control := range controls {
					if control != "" && source != "register" {
						continue
					}
					rows = append(rows, x86ScalarPrecisionOracleRow{op: "V" + scalar.op, input: scalar.input,
						output: scalar.output, source: source, control: control, mode: mode, vector: true})
				}
			}
		}
		if arch == "amd64" {
			// A high upper/destination bank forces the otherwise overlapping
			// unmasked EVEX row, including its independent m32/m64 tuple.
			for _, source := range []string{"register", "native", "FP"} {
				rows = append(rows, x86ScalarPrecisionOracleRow{op: "V" + scalar.op, input: scalar.input,
					output: scalar.output, source: source, mode: "plain", vector: true, high: true})
			}
		}
	}
	return rows
}

func (row x86ScalarPrecisionOracleRow) instruction() string {
	scalar, upper, destination := row.registers()
	op, source := row.op, fmt.Sprint("X", scalar)
	if row.source == "native" {
		source = "(AX)"
	} else if row.source == "FP" {
		source = "input+8(FP)"
	}
	if row.control != "" {
		op += "." + row.control
	}
	if row.mode == "zero" {
		op += ".Z"
	}
	if !row.vector {
		return fmt.Sprintf("%s %s,X%d", op, source, destination)
	}
	mask := ""
	if row.mode == "merge" || row.mode == "zero" {
		mask = ",K1"
	}
	return fmt.Sprintf("%s %s,X%d%s,X%d", op, source, upper, mask, destination)
}

func (row x86ScalarPrecisionOracleRow) registers() (source, upper, destination int) {
	if row.high {
		return 16, 17, 18
	}
	if !row.vector {
		return 0, 2, 2
	}
	return 0, 1, 2
}

func TestX86ScalarPrecisionCompleteTypedOperandAndControlMatrix(t *testing.T) {
	x86ScalarPrecisionOriginalProgram(t)
	for _, arch := range []string{"amd64", "386"} {
		rows := x86ScalarPrecisionOracleRows(arch)
		want := 45
		if arch == "386" {
			want = 17
		}
		if len(rows) != want {
			t.Fatal("complete independent precision source/control directory changed", arch, len(rows), want)
		}
		for _, row := range rows {
			t.Run(arch+"/"+row.instruction(), func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.instruction())
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
				if !known || err != nil || !effect.requiresResultProof || effect.dynamicMemory ||
					effect.flagsRead|effect.flagsDefined|effect.flagsKilled != 0 {
					t.Fatal("complete precision conversion source/upper/K/destination effect missing", effect, known, err)
				}
				reads, writes := make(map[int]bool), make(map[int]bool)
				for _, operand := range effect.operands {
					width := int64(16)
					if operand.index == 0 {
						width = int64(row.input)
					} else if operand.operand.Kind == OpReg && operand.operand.Reg == "K1" {
						width = 8
					}
					if operand.index < 0 || operand.index >= len(ins.Args) || operand.width != width ||
						!reflect.DeepEqual(operand.operand, ins.Args[operand.index]) {
						t.Fatal("scalar input tuple, upper carrier or K width changed", operand)
					}
					reads[operand.index] = reads[operand.index] || operand.read
					writes[operand.index] = writes[operand.index] || operand.write
				}
				last := len(ins.Args) - 1
				for index := range ins.Args {
					wantRead := index < last || !row.vector || row.mode == "merge"
					if reads[index] != wantRead || writes[index] != (index == last) {
						t.Fatal("conversion data, copied upper, merge or mask role was lost", index, reads, writes)
					}
				}
			})
		}
	}
}

func TestX86ScalarPrecisionSelectedBytesOldUpperAndAliases(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86ScalarPrecisionOracleRows(arch) {
			if row.source != "register" {
				continue
			}
			t.Run(arch+"/"+row.instruction(), func(t *testing.T) {
				for _, alias := range []string{"distinct", "source-destination", "upper-destination", "all"} {
					ins := x86ScalarLaneInstruction(t, row.instruction())
					source, base, destination := row.registers()
					if alias == "source-destination" || alias == "all" {
						source, ins.Args[0].Reg = destination, Reg(fmt.Sprint("X", destination))
					}
					if row.vector && (alias == "upper-destination" || alias == "all") {
						base, ins.Args[1].Reg = destination, Reg(fmt.Sprint("X", destination))
					}
					start, _, _ := row.registers()
					for register := start; register < start+3; register++ {
						for missing := -1; missing < 64; missing++ {
							state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward, masks: [8]bool{1: true}}
							for index := start; index < start+3; index++ {
								state.writeVector(index, 64, ^uint64(0), true)
							}
							state.pointerGP[5], state.callerAddressGP[6] = true, true
							if missing >= 0 {
								state.writeVector(register, 64, ^(uint64(1) << uint(missing)), true)
							}
							before, want := state.clone(), state.clone()
							input := x86CallerVectorByteMask(int64(row.input))
							output := x86CallerVectorByteMask(int64(row.output))
							valid := state.vectorBytes(source)&input == input &&
								(row.mode != "merge" || state.vectorBytes(destination)&output == output)
							if valid {
								defined := output | state.vectorBytes(base)&(0xffff&^output)
								want.writeVector(destination, 16, defined, !row.vector)
							}
							if accepted := x86ResultTransfer(ins, &state, nil, 0, arch); accepted != valid || !reflect.DeepEqual(state, want) {
								t.Fatal("precision conversion invented active FP/merge input, copied unknown upper bytes or changed unrelated state",
									alias, register, missing, accepted, valid, before, state, want)
							}
						}
					}
				}
			})
		}
	}
}

func TestX86ScalarPrecisionLogicalScalarReadRequiresExactOwnedBytes(t *testing.T) {
	for _, row := range x86ScalarPrecisionOracleRows("amd64") {
		if row.source != "FP" {
			continue
		}
		t.Run(row.instruction(), func(t *testing.T) {
			ins := x86ScalarLaneInstruction(t, row.instruction())
			_, upper, destination := row.registers()
			for missing := -1; missing < row.input; missing++ {
				for _, role := range []string{"defined", "owned"} {
					owned := make([]bool, 16)
					state := x86ResultState{fp: make([]bool, 16), masks: [8]bool{1: true}, flags: x86ByteFlagsAll}
					state.writeVector(upper, 64, ^uint64(0), true)
					state.writeVector(destination, 64, ^uint64(0), true)
					for at := 8; at < 8+row.input; at++ {
						owned[at], state.fp[at] = true, true
					}
					if missing >= 0 {
						if role == "defined" {
							state.fp[8+missing] = false
						} else {
							owned[8+missing] = false
						}
					}
					before := state.clone()
					if accepted := x86ResultTransfer(ins, &state, owned, 16, "amd64"); accepted != (missing < 0) ||
						missing >= 0 && !reflect.DeepEqual(state, before) {
						t.Fatal("scalar precision borrowed adjacent virtual bytes or missing owned input", role, missing, accepted)
					}
				}
			}
		})
	}
}

func TestX86ScalarPrecisionNativeAndMaskInputsRemainMandatory(t *testing.T) {
	for _, row := range x86ScalarPrecisionOracleRows("amd64") {
		if row.source == "FP" || row.source != "native" && row.mode != "merge" && row.mode != "zero" {
			continue
		}
		for _, unusedBool := range []bool{false, true} {
			extent, declaration := 0, "func Missing()"
			if unusedBool {
				extent, declaration = 1, "func Missing(unused bool)"
			}
			source := fmt.Sprintf("TEXT ·Missing(SB),4,$0-%d\n%s\nRET\n", extent, row.instruction())
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(fmt.Sprintf("%s/unused=%t/%s", row.instruction(), unusedBool, api), func(t *testing.T) {
					if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("Void/dead conversion invented active FP/native/K/merge input", err)
					}
				})
			}
		}
	}
}

func TestX86ScalarPrecisionTypedGrammarRejectsNonGoForms(t *testing.T) {
	for _, line := range []string{
		"CVTSS2SD Y0,X1", "CVTSD2SS M0,X1", "CVTSS2SD X16,X1", "CVTSD2SS.Z X0,X1",
		"VCVTSS2SD.RN_SAE X0,X1,X2", "VCVTSD2SS.SAE X0,X1,X2",
		"VCVTSS2SD.SAE (AX),X1,X2", "VCVTSD2SS.RN_SAE (AX),X1,X2",
		"VCVTSS2SD.Z X0,X1,X2", "VCVTSD2SS X0,X1,K0,X2",
		"VCVTSS2SD.BCST (AX),X1,X2", "VCVTSD2SS Y0,X1,X2", "VCVTSS2SD X0,Y1,X2",
		"VCVTSD2SS X0,X1,Z2", "VCVTSS2SD X0,X1", "VCVTSD2SS.RN_SAE.RD_SAE X0,X1,X2",
	} {
		t.Run(strings.ReplaceAll(line, " ", "_"), func(t *testing.T) {
			ins := x86ScalarLaneInstruction(t, line)
			if _, known, err := x86TypedInstructionByteEffect(ins.Op, ins, "amd64"); !known || err == nil {
				t.Fatal("known precision family lacks closed operands/control grammar", known, err)
			}
		})
	}
}
