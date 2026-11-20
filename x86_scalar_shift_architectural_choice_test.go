package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type x86ShiftChoiceCase struct {
	text        string
	valueChoice bool
	flagsChoice bool
}

// This independent finite basis complements the existing complete 148-row Go
// encoder oracle. It spans every mnemonic, width and input role, both kinds of
// architectural choice, high-byte preservation, native RMW and BMI2 sources.
// Missing inputs are not architectural choices.
func x86ShiftChoiceCases(arch string) []x86ShiftChoiceCase {
	widths := []string{"B", "W", "L", "Q"}
	if arch == "386" {
		widths = widths[:3]
	}
	var rows []x86ShiftChoiceCase
	for _, stem := range []string{"RCL", "RCR", "ROL", "ROR", "SAL", "SAR", "SHL", "SHR"} {
		for _, width := range widths {
			for _, operands := range []string{"CL,AX", "$2,AX", "CL,1(SI)"} {
				rows = append(rows, x86ShiftChoiceCase{stem + width + " " + operands, false, true})
			}
			if width == "B" {
				rows = append(rows, x86ShiftChoiceCase{stem + "B CL,AH", false, true})
			}
		}
	}
	for _, stem := range []string{"SHL", "SHR"} {
		for _, width := range widths[1:] {
			for _, operands := range []string{"CL,BX,AX", "$17,BX,AX", "CL,BX,1(SI)"} {
				rows = append(rows, x86ShiftChoiceCase{stem + width + " " + operands, width == "W", true})
			}
			if width == "W" {
				rows = append(rows,
					x86ShiftChoiceCase{stem + "W $16,BX,AX", false, true},
					x86ShiftChoiceCase{stem + "W CX,BX,AX", true, true})
			}
		}
	}
	for _, stem := range []string{"SARX", "SHLX", "SHRX", "RORX"} {
		for _, width := range []string{"L", "Q"} {
			count := "CX"
			if stem == "RORX" {
				count = "$2"
			}
			for _, source := range []string{"BX", "1(SI)"} {
				rows = append(rows, x86ShiftChoiceCase{stem + width + " " + count + "," + source + ",AX", false, false})
			}
		}
	}
	return rows
}

func x86ShiftChoiceOriginalBytes(t *testing.T, arch string, rows []x86ShiftChoiceCase) [][]byte {
	t.Helper()
	var source strings.Builder
	for _, row := range rows {
		source.WriteString(row.text + "\n")
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, arch, source.String()+"RET")
	if len(pcs) != len(rows)+1 || len(code) == 0 || code[len(code)-1] != 0xc3 {
		t.Fatal("incomplete original Go scalar opcode bytes or instruction boundaries")
	}
	result := make([][]byte, len(rows))
	for index := range rows {
		result[index] = append([]byte(nil), code[pcs[index]:pcs[index+1]]...)
	}
	return result
}

func x86ShiftChoiceSource(arch, instruction string, code []byte, control string, observeAll bool) (string, string) {
	word, move := goWordSize(arch), "MOVQ"
	if arch == "386" {
		move = "MOVL"
	}
	frame := 5 * word
	declaration := "func Choice(out *[48]byte,memory *[16]byte,x,y,count uintptr)\n"
	if control == "unused bool" || strings.HasPrefix(control, "unused bool/") {
		frame++
		declaration = "func Choice(out *[48]byte,memory *[16]byte,x,y,count uintptr,unused bool)\n"
		control = strings.TrimPrefix(strings.TrimPrefix(control, "unused bool"), "/")
	}
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·Choice(SB),4,$0-%d\n%s out+0(FP),DI\n", frame, move)
	if control == "numeric address" {
		source.WriteString("MOVL $1,SI\n")
	} else if control != "missing address" {
		fmt.Fprintf(&source, "%s memory+%d(FP),SI\n", move, word)
	}
	if control == "missing old high" {
		fmt.Fprintf(&source, "MOVW x+%d(FP),AX\n", 2*word)
	} else if control != "missing x" {
		fmt.Fprintf(&source, "%s x+%d(FP),AX\n", move, 2*word)
	}
	if control != "missing y" {
		fmt.Fprintf(&source, "%s y+%d(FP),BX\n", move, 3*word)
	}
	if control != "missing count" {
		fmt.Fprintf(&source, "%s count+%d(FP),CX\n", move, 4*word)
	}
	// Seed independently of data/count under test. A missing AX/BX/CX must
	// fail at its actual consumer, not accidentally at this FLAGS producer.
	switch control {
	case "missing flags", "missing carry":
	case "foreign AF":
		source.WriteString("MOVL $7,DX\nANDL $1,DX\n")
	case "carry only":
		source.WriteString("STC\n")
	default:
		source.WriteString("MOVL $0x7fffffff,DX\nADDL $1,DX\nSTC\n")
	}
	if code == nil {
		source.WriteString(instruction + "\n")
	} else {
		for _, value := range code {
			fmt.Fprintf(&source, "BYTE $%d\n", value)
		}
	}
	fmt.Fprintf(&source, "%s AX,0(DI)\n", move)
	if control != "missing carry" {
		if control == "carry only" {
			source.WriteString("SETEQ 32(DI)\n")
		} else {
			source.WriteString("SETCS 32(DI)\nSETOS 33(DI)\n")
		}
	}
	if observeAll {
		source.WriteString("SETEQ 34(DI)\nSETMI 35(DI)\nSETPS 36(DI)\nLAHF\nMOVB AH,37(DI)\n")
	}
	source.WriteString("RET\n")
	return source.String(), declaration
}

func TestX86ScalarShiftArchitecturalChoiceIndependentDirectory(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		rows := x86ShiftChoiceCases(arch)
		want, flags := 142, 126
		if arch == "386" {
			want, flags = 112, 96
		}
		seen, valueChoices, flagChoices := make(map[string]bool), 0, 0
		for _, row := range rows {
			if seen[row.text] {
				t.Fatal("duplicate independent architectural-outcome witness", arch, row.text)
			}
			seen[row.text] = true
			if row.valueChoice {
				valueChoices++
			}
			if row.flagsChoice {
				flagChoices++
			}
		}
		if len(rows) != want || valueChoices != 8 || flagChoices != flags {
			t.Fatal("complete outcome/input-role basis changed", arch, len(rows), valueChoices, flagChoices)
		}
	}
}

func x86ShiftChoiceObjectBatch(t *testing.T, batch int) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required for complete architectural-outcome objects")
	}
	type originals struct {
		rows []x86ShiftChoiceCase
		code [][]byte
	}
	cache := make(map[string]originals)
	for _, target := range x86RawReturnTargets {
		rows := x86ShiftChoiceCases(target.arch)
		start, end := batch*32, (batch+1)*32
		if start >= len(rows) {
			continue // The independently pinned 386 basis has four batches, not five.
		}
		if end > len(rows) {
			end = len(rows)
		}
		original, exists := cache[target.arch]
		if !exists {
			original.rows = rows[start:end]
			original.code = x86ShiftChoiceOriginalBytes(t, target.arch, original.rows)
			cache[target.arch] = original
		}
		for _, raw := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/raw=%t", target.triple, raw), func(t *testing.T) {
				var source, declarations strings.Builder
				for index, row := range original.rows {
					var code []byte
					if raw {
						code = original.code[index]
					}
					body, declaration := x86ShiftChoiceSource(target.arch, row.text, code, "", true)
					name := fmt.Sprint("Choice", start+index)
					source.WriteString(strings.ReplaceAll(body, "Choice", name))
					declarations.WriteString(strings.ReplaceAll(declaration, "Choice", name))
				}
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
						if err != nil || ir == "" {
							t.Error("actual initialized opcode inputs cannot observe conditional ISA choices as finite values", err)
							return
						}
						for _, body := range []string{ir, x86DwordProductIROptimize(t, ir)} {
							compileLLVMToObject(t, llc, target.triple, "scalar-choices.ll", "scalar-choices.o", body)
						}
						x86PackedStringCompileObject(t, llc, target.triple, ir, "-O2")
					})
				}
			})
		}
	}
}

func TestX86ScalarShiftArchitecturalChoiceObjectsBatch0(t *testing.T) {
	x86ShiftChoiceObjectBatch(t, 0)
}

func TestX86ScalarShiftArchitecturalChoiceObjectsBatch1(t *testing.T) {
	x86ShiftChoiceObjectBatch(t, 1)
}

func TestX86ScalarShiftArchitecturalChoiceObjectsBatch2(t *testing.T) {
	x86ShiftChoiceObjectBatch(t, 2)
}

func TestX86ScalarShiftArchitecturalChoiceObjectsBatch3(t *testing.T) {
	x86ShiftChoiceObjectBatch(t, 3)
}

func TestX86ScalarShiftArchitecturalChoiceObjectsBatch4(t *testing.T) {
	x86ShiftChoiceObjectBatch(t, 4)
}

func TestX86ScalarShiftArchitecturalChoiceDefinedCountControls(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		widths := []string{"B", "W", "L", "Q"}
		if arch == "386" {
			widths = widths[:3]
		}
		var source, declarations strings.Builder
		index := 0
		for _, stem := range []string{"RCL", "RCR", "ROL", "ROR", "SAL", "SAR", "SHL", "SHR"} {
			for _, width := range widths {
				for _, count := range []string{"$0", "$1"} {
					body, declaration := x86ShiftChoiceSource(arch, stem+width+" "+count+",AX", nil, "", false)
					name := fmt.Sprint("Choice", index)
					index++
					source.WriteString(strings.ReplaceAll(body, "Choice", name))
					declarations.WriteString(strings.ReplaceAll(declaration, "Choice", name))
				}
			}
		}
		triple := x86AddressMemoryTargets(arch)[0]
		x86LEAActualTargetGoObject(t, arch, triple, source.String())
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(arch+"/"+api, func(t *testing.T) {
				if ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), arch, triple, api); err != nil || ir == "" {
					t.Fatal("fully defined count0/count1 CF/OF control failed before any architectural choice", err)
				}
			})
		}
	}
}

func TestX86ScalarShiftArchitecturalChoiceCannotRepairMissingFacts(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range []struct {
			instruction, control string
			observeAll           bool
		}{
			{"SHLW CL,BX,AX", "missing x", false},
			{"SHLW CL,BX,AX", "missing y", false},
			{"SHLW CL,BX,AX", "missing count", false},
			{"SHLW $17,BX,AX", "missing old high", false},
			{"RCLB CL,AX", "missing carry", false},
			{"SHLL $0,AX", "missing flags", false},
			{"SHLL CL,AX", "missing flags", false},
			{"RCLL $1,AX", "carry only", false},
			{"SHLXL CX,BX,AX", "missing flags", false},
			{"RORXL $2,BX,AX", "missing flags", false},
			{"ROLW $0,AX", "foreign AF", true},
			{"SHLW CL,BX,1(SI)", "missing address", false},
			{"SHLW CL,BX,1(SI)", "numeric address", false},
			{"SHLW CL,BX,AX", "unused bool/missing x", false},
			{"SHLW CL,BX,AX", "unused bool/missing count", false},
			{"RCLB CL,AX", "unused bool/missing carry", false},
		} {
			source, declaration := x86ShiftChoiceSource(arch, row.instruction, nil, row.control, row.observeAll)
			triple := x86AddressMemoryTargets(arch)[0]
			x86LEAActualTargetGoObject(t, arch, triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+row.instruction+"/"+row.control+"/"+api, func(t *testing.T) {
					if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("ISA choice borrowed a missing input, retained flag/high byte or native address", err)
					}
				})
			}
		}
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(arch+"/unusedBoolPositive/"+api, func(t *testing.T) {
				source, declaration := x86ShiftChoiceSource(arch, "SHLW CL,BX,AX", nil, "unused bool", true)
				triple := x86AddressMemoryTargets(arch)[0]
				x86LEAActualTargetGoObject(t, arch, triple, source)
				if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api); ir == "" || err != nil {
					t.Fatal("valid initialized Void program with unused bool lost its independent scalar outcome", err)
				}
			})
		}
	}
}

func TestX86ScalarShiftArchitecturalChoiceNeedsPairedMaterialization(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range []string{"SHLW CL,BX,AX", "SHRW CX,BX,AX", "SHLW $17,BX,AX", "SHRW $-1,BX,AX"} {
			t.Run(arch+"/"+row, func(t *testing.T) {
				instruction := x86ScalarLaneInstruction(t, row)
				if _, known, err := x86TypedScalarShiftByteEffect(instruction.Op, instruction, arch); !known || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("a format/byte-effect query materialized an unspecified output without its paired emitter", known, err)
				}
				for _, consumer := range x86ResultGPSIMDConsumers {
					state := x86ResultState{flags: x86ByteFlagsAll}
					for register := range state.gp {
						state.gp[register] = 0xff
					}
					before := state.clone()
					if consumer.step(instruction, &state, nil, 0, arch) || !reflect.DeepEqual(state, before) {
						t.Fatal("declaration-only consumer borrowed a paired architectural-choice role", consumer.name)
					}
				}
			})
		}
	}
}
