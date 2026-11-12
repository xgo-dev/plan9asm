package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestX86PackedShiftResultIndependentGoGrammarAxes(t *testing.T) {
	inventory := make(map[string]bool)
	for _, row := range x86PackedShiftResultRows() {
		inventory[strings.Fields(row.row)[0]] = true
	}
	var names []string
	for name := range inventory {
		names = append(names, name)
	}
	sort.Strings(names)
	if !reflect.DeepEqual(names, x86PackedShiftNames()) {
		t.Fatal("independent whole-family denominator changed", names)
	}
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			var rows []string
			for _, name := range names {
				vector := strings.HasPrefix(name, "V")
				perLane := strings.Contains(name, "LLV") || strings.Contains(name, "RLV")
				byteShift := strings.HasSuffix(name, "DQ") || strings.HasSuffix(name, "O")
				banks := []string{"X"}
				if vector {
					banks = []string{"X", "Y", "Z"}
				}
				for _, bank := range banks {
					if !perLane {
						first, last := -128, 127
						if vector {
							last = 255
						}
						if bank == "Z" {
							first = 0
						}
						for immediate := first; immediate <= last; immediate++ {
							row := fmt.Sprintf("%s $%d,%s1", name, immediate, bank)
							if vector {
								row += "," + bank + "2"
							}
							rows = append(rows, row)
						}
					}
					limit := 32
					if arch == "386" && bank == "Z" {
						// cmd/asm accepts high named X/Y banks in mode32, but
						// rejects high Z. Neither supplies a physical register.
						limit = 8
					}
					if !vector {
						limit = 16
						if arch == "386" {
							limit = 8
						}
					}
					for index := 0; index < limit; index++ {
						data := fmt.Sprintf("%s%d", bank, index)
						if !vector {
							rows = append(rows, name+" $7,"+data)
							if !byteShift {
								rows = append(rows, name+" "+data+",X1")
							}
							continue
						}
						if !perLane {
							rows = append(rows, name+" $7,"+data+","+bank+"2", name+" $7,"+bank+"1,"+data)
						}
						if !byteShift {
							countBank := "X"
							if perLane {
								countBank = bank
							}
							rows = append(rows, fmt.Sprintf("%s %s%d,%s1,%s2", name, countBank, index, bank, bank),
								name+" "+countBank+"0,"+data+","+bank+"2", name+" "+countBank+"0,"+bank+"1,"+data)
						}
					}
				}
			}
			if arch == "386" {
				rows = append(rows, "PSRLQ $4294967297,X1", "PSRLDQ $-4294967297,X1", "VPSRLQ $4294967551,X1,X2", "VPSRLDQ $4294967551,X1,X2")
			}
			source := "TEXT f(SB),4,$0-0\n" + strings.Join(rows, "\n") + "\nRET\n"
			goAssemblerOracleOutput(t, arch, source, "", true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			for index, row := range rows {
				ins := file.Funcs[0].Instrs[index+1]
				originalCount := ins.Args[0]
				context := false
				if arch == "386" {
					for _, arg := range ins.Args {
						reg, valid := amd64VectorRegisterIndex(arg.Reg, amd64VectorByteWidth(arg.Reg))
						context = context || valid && reg >= 8
					}
				}
				form, known, err := x86PackedShiftProperties(ins.Op, ins, arch)
				if !known || context && !errors.Is(err, ErrProbeNeedsContext) || !context && err != nil {
					t.Fatal(row, err)
				}
				if !context && ins.Args[0].Kind == OpImm && uint8(form.countOperand.Imm) != uint8(ins.Args[0].Imm) {
					t.Fatal("classified immediate changed encoded count", row)
				}
				if !reflect.DeepEqual(originalCount, ins.Args[0]) {
					t.Fatal("classification rewrote the retained source", row)
				}
			}
			t.Logf("%d actual Go forms, with physical mode32 context kept separate", len(rows))
		})
	}
}

func TestX86PackedShiftResultMode32ClassifiedImmediateObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	source := "TEXT ·view(SB),4,$0-4\nMOVL $7,AX\n"
	for dword := 0; dword < 4; dword++ {
		source += fmt.Sprintf("PINSRD $%d,AX,X1\n", dword)
	}
	source += "PSRLQ $4294967297,X1\nPSRLDQ $-4294967297,X1\nVPSRLQ $4294967551,X1,X2\nVPSRLDQ $4294967551,X2,X1\nPEXTRD $0,X1,AX\nMOVL AX,ret+0(FP)\nRET\n"
	for _, target := range x86RawReturnTargets {
		if target.arch != "386" {
			continue
		}
		x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
		for _, api := range []string{"text", "module", "Go"} {
			ir, err := x86ScalarFPBitViewAPI(t, source, "func view() uint32\n", target.arch, target.triple, api)
			if err != nil {
				t.Fatal(target.triple, api, err)
			}
			compileLLVMToObject(t, llc, target.triple, "classified-shift.ll", "classified-shift.o", ir)
		}
	}
}

func TestX86PackedShiftResultMode32HighZGoRejections(t *testing.T) {
	seen := make(map[string]bool)
	for _, candidate := range x86PackedShiftResultRows() {
		name := strings.Fields(candidate.row)[0]
		if !strings.HasPrefix(name, "V") || seen[name] {
			continue
		}
		seen[name] = true
		for index := 8; index < 32; index++ {
			count := "$7"
			if strings.Contains(name, "LLV") || strings.Contains(name, "RLV") {
				count = "Z0"
			}
			row := fmt.Sprintf("%s %s,Z%d,Z2", name, count, index)
			goAssemblerOracleOutput(t, "386", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", false)
			ins := x86ScalarLaneInstruction(t, row)
			if _, known, err := x86PackedShiftProperties(ins.Op, ins, "386"); !known || err == nil {
				t.Fatal("mode32 physical Z register admitted", row)
			}
		}
	}
}

func TestX86PackedShiftResultUnresolvedFormsCannotEmit(t *testing.T) {
	for _, row := range []string{"PSLLW $0,X1", "PSRLDQ $0,X1", "VPSRLQ $0,X1,X2", "VPSRLDQ $0,X1,X2"} {
		for _, mutation := range []string{"floating", "unresolved"} {
			ins := x86ScalarLaneInstruction(t, row)
			if mutation == "floating" {
				ins.Args[0].ImmIsFloat = true
			} else {
				ins.Args[0].ImmRaw = "missing"
			}
			ctx, output := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, nil)
			before := output.Len()
			if _, _, err := ctx.lowerX86PackedShift(ins.Op, ins); err == nil || output.Len() != before {
				t.Fatal("noninteger immediate emitted IR", row, mutation, err)
			}
		}
	}
	for _, mutation := range []string{"displacement", "index"} {
		ins := x86ScalarLaneInstruction(t, "VPSRLQ (AX),X1,X2")
		if mutation == "displacement" {
			ins.Args[0].Mem.OffRaw = "missing"
		} else {
			ins.Args[0].Mem.IndexExt = "unknown"
		}
		if _, known, err := x86PackedShiftProperties(ins.Op, ins, "amd64"); !known || err == nil {
			t.Fatal("unresolved memory accepted", mutation)
		}
	}
}
