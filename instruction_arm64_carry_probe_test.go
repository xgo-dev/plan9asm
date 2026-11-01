package plan9asm

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func arm64CarryProbeOpcodes() []string {
	return []string{"ADC", "ADCW", "ADCS", "ADCSW", "SBC", "SBCW", "SBCS", "SBCSW", "NGC", "NGCW", "NGCS", "NGCSW"}
}

func arm64CarryProbeForms(op string) []string {
	if strings.HasPrefix(op, "NGC") {
		return []string{"R1,R2", "ZR,R2", "R1,ZR", "ZR,ZR", "R0,R0"}
	}
	return []string{
		"R1,R2", "R1,R2,R3", "ZR,R2", "ZR,R2,R3", "$0,R2", "$0,R2,R3",
		"R1,ZR", "R1,ZR,ZR", "ZR,ZR,ZR", "R0,R0,R0", "R1,R2,R30",
	}
}

func arm64CarryProbeFile(t *testing.T, body string) *File {
	t.Helper()
	file, err := Parse(ArchARM64, "TEXT carryProbe(SB),516,$0-0\n"+body+"\nB (ZR)\n")
	if err != nil {
		t.Fatal(err)
	}
	return file
}

func arm64CarryProbeBody(file *File) []Instr {
	instrs := file.Funcs[0].Instrs
	return instrs[1 : len(instrs)-1]
}

func arm64CarryProbeTranslate(file *File) (string, error) {
	return Translate(file, Options{Goarch: "arm64", TargetTriple: arm64LinuxGNUTriple,
		Sigs: map[string]FuncSig{"carryProbe": {Name: "carryProbe", Ret: Void}},
	})
}

func arm64CarryProbeCheckCompleteGoTable(t *testing.T, goroot string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(goroot, "src/cmd/internal/obj/arm64/asm7.go"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	versionData, err := os.ReadFile(filepath.Join(goroot, "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	version := strings.SplitN(strings.TrimSpace(string(versionData)), "\n", 2)[0]
	columns, err := arm64CarryProbeGoOptabColumns(source, version)
	if err != nil {
		t.Fatal(err)
	}
	var aliases []string
	for _, family := range []struct {
		name string
		rows []string
	}{
		{"AADC", []string{
			"{AADC,C_ZREG,C_ZREG,C_NONE,C_ZREG,C_NONE,1,4,0,0,0},",
			"{AADC,C_ZREG,C_NONE,C_NONE,C_ZREG,C_NONE,1,4,0,0,0},",
		}},
		{"ANGC", []string{"{ANGC,C_ZREG,C_NONE,C_NONE,C_ZREG,C_NONE,17,4,0,0,0},"}},
	} {
		rows := regexp.MustCompile(`(?m)^\s*\{`+family.name+`,[^\n]+`).FindAllString(source, -1)
		for index, row := range rows {
			rows[index] = strings.Join(strings.Fields(row), "")
		}
		if columns == 10 {
			// The verified old schema lacks only the a5 destination column.
			// Every other operand, encoder and effect field stays exact.
			for index, row := range family.rows {
				fields := strings.Split(row, ",")
				family.rows[index] = strings.Join(append(fields[:5:5], fields[6:]...), ",")
			}
		}
		if !reflect.DeepEqual(rows, family.rows) {
			t.Fatalf("complete Go %s rows changed: got %v want %v", family.name, rows, family.rows)
		}
		start := strings.Index(source, "case "+family.name+":")
		if start < 0 {
			t.Fatalf("missing Go opcode alias registration: %s", family.name)
		}
		block := source[start+len("case "+family.name+":"):]
		if end := strings.Index(block, "\n\t\tcase "); end >= 0 {
			block = block[:end]
		}
		aliases = append(aliases, strings.TrimPrefix(family.name, "A"))
		for _, match := range regexp.MustCompile(`oprangeset\(A([A-Z0-9]+), t\)`).FindAllStringSubmatch(block, -1) {
			aliases = append(aliases, match[1])
		}
	}
	want := arm64CarryProbeOpcodes()
	sort.Strings(aliases)
	sort.Strings(want)
	if !reflect.DeepEqual(aliases, want) {
		t.Fatalf("complete Go carry alias family changed: got %v want %v", aliases, want)
	}

	data, err = os.ReadFile(filepath.Join(goroot, "src/cmd/internal/obj/arm64/obj7.go"))
	if err != nil {
		t.Fatal(err)
	}
	source = string(data)
	start := strings.Index(source, "var zrReplace = map[obj.As]bool{")
	if start < 0 {
		t.Fatal("Go source zero-alias table missing")
	}
	block := source[start:]
	end := strings.Index(block, "\n}")
	if end < 0 {
		t.Fatal("Go source zero-alias table is not complete")
	}
	block = block[:end]
	for _, op := range arm64CarryProbeOpcodes() {
		present := regexp.MustCompile(`\bA` + op + `:\s+true,`).MatchString(block)
		if present == strings.HasPrefix(op, "NGC") {
			t.Fatalf("Go %s immediate-zero alias changed: present=%v", op, present)
		}
	}
	t.Logf("actual %s: complete %d-column Optab, all 12 carry aliases and exact zero-replace membership", version, columns)
}

func TestARM64CarryProbeSingleCompleteForms(t *testing.T) {
	for _, op := range arm64CarryProbeOpcodes() {
		for _, operands := range arm64CarryProbeForms(op) {
			spelling := op + " " + operands
			t.Run(spelling, func(t *testing.T) {
				file := arm64CarryProbeFile(t, spelling)
				requireARM64GoAssemblerResult(t, file.Funcs[0].Instrs[0].Raw+"\n"+spelling+"\nB (ZR)\n", true)
				ins := arm64CarryProbeBody(file)[0]
				before := ins
				before.Args = append([]Operand(nil), ins.Args...)
				if err := ProbeInstruction(ArchARM64, "arm64", ins); err != nil {
					t.Errorf("valid single carry form needs its own real CMP fixture: %v", err)
				}
				if !reflect.DeepEqual(ins, before) {
					t.Fatal("single-form fixture mutated the original instruction")
				}
			})
		}
	}
}

func TestARM64CarryProbeRetainsSequenceAndSourceFlagInputs(t *testing.T) {
	for _, op := range arm64CarryProbeOpcodes() {
		operands := "R1,R2,R3"
		if strings.HasPrefix(op, "NGC") {
			operands = "R1,R2"
		}
		spelling := op + " " + operands
		for _, body := range []string{spelling, spelling + "\nCMP R0,R0", "CMP R0,R0\n" + spelling} {
			t.Run(body, func(t *testing.T) {
				file := arm64CarryProbeFile(t, body)
				sequenceErr := ProbeInstructionSequence(ArchARM64, "arm64", arm64CarryProbeBody(file))
				_, sourceErr := arm64CarryProbeTranslate(file)
				for _, err := range []error{sequenceErr, sourceErr} {
					if strings.HasPrefix(body, "CMP ") {
						if err != nil {
							t.Fatalf("actual prior CMP source was rejected: %v", err)
						}
					} else if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "unknown NZCV bits 0x2") {
						t.Fatalf("missing or late CMP supplied the original carry input: %v", err)
					}
				}
			})
		}
	}
}

func TestARM64CarryProbeRejectsFormsOutsideGoGrammar(t *testing.T) {
	for _, op := range arm64CarryProbeOpcodes() {
		forms := []string{"R1", "R1,R2,R3,R4", "RSP,R2", "R1,RSP", "R1<<1,R2", "$1,R2", "(R1),R2"}
		if strings.HasPrefix(op, "NGC") {
			forms = append(forms, "R1,R2,R3", "$0,R2")
		} else {
			forms = append(forms, "R1,RSP,R2", "R1,R2,RSP", "R1.UXTW,R2,R3")
		}
		for _, operands := range forms {
			t.Run(op+" "+operands, func(t *testing.T) {
				spelling := op + " " + operands
				requireARM64GoAssemblerResult(t, "TEXT invalidCarry(SB),516,$0-0\nCMP R0,R0\n"+spelling+"\nB (ZR)\n", false)
				file := arm64CarryProbeFile(t, spelling)
				if err := ProbeInstruction(ArchARM64, "arm64", arm64CarryProbeBody(file)[0]); err == nil {
					t.Fatal("single-form fixture accepted a Go-invalid carry operand")
				}
			})
		}
		for _, suffix := range []string{".P", ".W", ".S"} {
			t.Run(op+suffix, func(t *testing.T) {
				spelling := op + suffix + " R1,R2"
				requireARM64GoAssemblerResult(t, "TEXT invalidCarry(SB),516,$0-0\n"+spelling+"\nB (ZR)\n", false)
				file := arm64CarryProbeFile(t, spelling)
				if err := ProbeInstruction(ArchARM64, "arm64", arm64CarryProbeBody(file)[0]); err == nil {
					t.Fatal("single-form fixture accepted a Go-invalid carry suffix")
				}
			})
		}
	}
}

func TestARM64CarryProbeDoesNotSupplyOtherConditionFlags(t *testing.T) {
	for _, body := range []string{"CSET EQ,R1", "CSEL CS,R1,R2,R3", "CCMNW EQ,R1,$1,$0", "CSINVW MI,R1,R2,R3", "FCCMPD VS,F0,F1,$0"} {
		t.Run(body, func(t *testing.T) {
			file := arm64CarryProbeFile(t, body)
			if err := ProbeInstruction(ArchARM64, "arm64", arm64CarryProbeBody(file)[0]); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("carry fixture supplied a foreign condition's flags: %v", err)
			}
		})
	}
}

func TestARM64AlwaysConditionProbeNeedsNoFlags(t *testing.T) {
	for _, spelling := range []string{
		"CCMNW AL,R26,$20,$11", "CCMNW AL,R19,R24,$7", "CSELW AL,R24,R16,R10",
		"FCCMPD AL,F0,F9,$0", "FCCMPED AL,F0,F14,$11", "FCCMPES AL,F7,F14,$1", "FCCMPS AL,F31,F5,$5",
		"CSINC AL,R17,R26,R26", "CSINCW AL,R11,R25,R21", "CSINV AL,R30,R6,R21", "CSINV AL,R26,R12,R30",
		"CSINV AL,ZR,ZR,ZR", "CSINVW AL,R23,R21,R5", "CSINVW AL,R27,R21,R5", "CSINVW AL,ZR,ZR,R5",
		"CSNEG AL,R26,R19,R21", "CSNEGW AL,R4,R5,R0",
	} {
		t.Run(spelling, func(t *testing.T) {
			file := arm64CarryProbeFile(t, spelling)
			requireARM64GoAssemblerResult(t, "TEXT alwaysCondition(SB),516,$0-0\n"+spelling+"\nB (ZR)\n", true)
			if mask, err := arm64ConditionFlags("AL"); err != nil || mask != 0 {
				t.Fatalf("AL is not a constant predicate: mask=%#x err=%v", mask, err)
			}
			if err := ProbeInstruction(ArchARM64, "arm64", arm64CarryProbeBody(file)[0]); err != nil {
				t.Fatal(err)
			}
			if err := ProbeInstructionSequence(ArchARM64, "arm64", arm64CarryProbeBody(file)); err != nil {
				t.Fatal(err)
			}
			if _, err := arm64CarryProbeTranslate(file); err != nil {
				t.Fatal(err)
			}
			conditional := arm64CarryProbeFile(t, strings.Replace(spelling, " AL,", " EQ,", 1))
			if err := ProbeInstruction(ArchARM64, "arm64", arm64CarryProbeBody(conditional)[0]); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("non-AL condition lost its original flag input: %v", err)
			}
		})
	}
}

func TestARM64AlwaysConditionProbeMatchesCompleteGoConditions(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(testGOROOT(t), "src/cmd/internal/obj/arm64/list7.go"))
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?s)var strcond = \[16\]string\{(.*?)\n\}`).FindSubmatch(data)
	if len(block) != 2 {
		t.Fatal("complete Go ARM64 condition-name table changed")
	}
	var names []string
	for _, match := range regexp.MustCompile(`"([A-Z]+)"`).FindAllSubmatch(block[1], -1) {
		names = append(names, string(match[1]))
	}
	want := []string{"EQ", "NE", "HS", "LO", "MI", "PL", "VS", "VC", "HI", "LS", "GE", "LT", "GT", "LE", "AL", "NV"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("complete Go condition names changed: got %v want %v", names, want)
	}
	for _, condition := range names {
		t.Run(condition, func(t *testing.T) {
			spelling := "CSEL " + condition + ",R1,R2,R3"
			requireARM64GoAssemblerResult(t, "TEXT condition(SB),516,$0-0\n"+spelling+"\nB (ZR)\n", true)
			file := arm64CarryProbeFile(t, spelling)
			err := ProbeInstruction(ArchARM64, "arm64", arm64CarryProbeBody(file)[0])
			if condition == "AL" || condition == "NV" {
				if mask, maskErr := arm64ConditionFlags(condition); maskErr != nil || mask != 0 || err != nil {
					t.Fatalf("constant condition needs flags: mask=%#x maskErr=%v probe=%v", mask, maskErr, err)
				}
			} else if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("nonconstant %s lost its source-defined flags: %v", condition, err)
			}
		})
	}
}

func TestARM64CarryProbeDoesNotInventSyscallContext(t *testing.T) {
	for _, spelling := range []string{"SVC", "SVC $0", "SVC $7165"} {
		t.Run(spelling, func(t *testing.T) {
			file := arm64CarryProbeFile(t, spelling)
			ins := arm64CarryProbeBody(file)[0]
			before := ins
			before.Args = append([]Operand(nil), ins.Args...)
			if err := ProbeInstruction(ArchARM64, "arm64", ins); err != nil {
				t.Fatalf("original Linux syscall probe acquired virtual flags as GP scratch: %v", err)
			}
			if err := ProbeInstructionSequence(ArchARM64, "arm64", []Instr{ins}); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(ins, before) {
				t.Fatal("syscall probe acquired invented entry instructions")
			}
			if _, err := arm64CarryProbeTranslate(file); err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{
				"carryProbe": {Name: "carryProbe", Ret: Void},
			}}); !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "requires an explicit ARM64 target") {
				t.Fatalf("missing original syscall target was invented: %v", err)
			}
		})
	}
}
