package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The directory below is independent of the production descriptor. These are
// the complete named GP extension rows in the actual Go x86 encoder. The
// observation establishes numerical byte knowledge only, never pointer/frame
// permissions or an initialized ABI0 entry register.
func TestX86ABI0ResultTypedExtensionsCompleteDeclaredBytes(t *testing.T) {
	rows := []struct {
		op        string
		source    int
		result    int
		reject386 bool
	}{
		{"MOVBWSX", 1, 2, false}, {"MOVBWZX", 1, 2, false},
		{"MOVBLSX", 1, 4, false}, {"MOVBLZX", 1, 4, false},
		{"MOVBQSX", 1, 8, true}, {"MOVBQZX", 1, 8, true},
		{"MOVWLSX", 2, 4, false}, {"MOVWLZX", 2, 4, false},
		{"MOVWQSX", 2, 8, true}, {"MOVWQZX", 2, 8, true},
		{"MOVLQSX", 4, 8, true}, {"MOVLQZX", 4, 8, false},
		{"MOVSWW", 2, 2, false}, {"MOVZWW", 2, 2, false},
	}
	for _, arch := range []string{"amd64", "386"} {
		word, typ, move := 8, "uint64", "MOVQ"
		if arch == "386" {
			word, typ, move = 4, "uint32", "MOVL"
		}
		for _, row := range rows {
			for _, input := range []string{"AX", "x+0(FP)", "value-16(SP)"} {
				t.Run(arch+"/"+row.op+"/"+input, func(t *testing.T) {
					body := fmt.Sprintf("%s x+0(FP),AX\n%s $0,BX\n%s AX,value-16(SP)\n%s %s,BX\n%s BX,ret0+%d(FP)\nRET",
						move, move, move, row.op, input, move, word)
					_, _, sig, source := x86ResultInitializationFixture(t, arch, "func Value(x "+typ+") "+typ, body)
					source = strings.Replace(source, ",$0-", ",$32-", 1)
					goAssemblerOracleOutput(t, arch, source, "", !row.reject386 || arch != "386")
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					err = CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch)
					if arch == "386" && row.reject386 {
						if !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatalf("Go-rejected mode acquired result knowledge: %v", err)
						}
						return
					}
					if err != nil {
						t.Fatalf("Go-accepted extension numerical effect missing: %v\n%s", err, source)
					}
				})
			}
		}
	}
}

func TestX86ABI0ResultTypedExplicitMultiplyCompleteForms(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, typ, move := 8, "uint64", "MOVQ"
		if arch == "386" {
			word, typ, move = 4, "uint32", "MOVL"
		}
		for _, suffix := range []string{"W", "L", "Q"} {
			for _, form := range []string{
				"IMUL%s AX,BX", "IMUL%s x+0(FP),BX", "IMUL%s value-16(SP),BX",
				"IMUL%s $-7,BX", "IMUL%s $65537,BX",
				"IMUL3%s $-7,AX,BX", "IMUL3%s $65537,x+0(FP),BX", "IMUL3%s $65537,value-16(SP),BX",
			} {
				instruction := fmt.Sprintf(form, suffix)
				t.Run(arch+"/"+instruction, func(t *testing.T) {
					body := fmt.Sprintf("%s x+0(FP),AX\n%s $3,BX\n%s AX,value-16(SP)\n%s\n%s BX,ret0+%d(FP)\nRET",
						move, move, move, instruction, move, word)
					_, _, sig, source := x86ResultInitializationFixture(t, arch, "func Value(x "+typ+") "+typ, body)
					source = strings.Replace(source, ",$0-", ",$32-", 1)
					rejected := arch == "386" && suffix == "Q"
					goAssemblerOracleOutput(t, arch, source, "", !rejected)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					err = CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch)
					if rejected {
						if !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatalf("Go-rejected multiplication acquired knowledge: %v", err)
						}
						return
					}
					if err != nil {
						t.Fatalf("Go-accepted explicit multiply effect missing: %v\n%s", err, source)
					}
				})
			}
		}
	}
}

func TestX86ABI0ResultTypedMultiplyOnlyDefinesCFAndOF(t *testing.T) {
	for _, condition := range []string{"CC", "CS", "EQ", "NE", "GE", "LT", "GT", "LE", "HI", "LS", "MI", "PL", "OC", "OS", "PC", "PS"} {
		t.Run(condition, func(t *testing.T) {
			body := "MOVL $3,AX\nCMPL AX,$0\nIMUL3L $7,AX,AX\nSET" + condition + " ret0+0(FP)\nRET"
			_, file, sig, source := x86ResultInitializationFixture(t, "amd64", "func Value() uint8", body)
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64")
			defined := condition == "CC" || condition == "CS" || condition == "OC" || condition == "OS"
			if defined && err != nil {
				t.Fatalf("defined multiply flags remain unknown: %v", err)
			}
			if !defined && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("multiply inherited undefined old comparison flags: %v", err)
			}
		})
	}
}

func TestX86ABI0ResultTypedGPUnknownAliasAndAddressStayContext(t *testing.T) {
	for name, body := range map[string]string{
		"undefined extension source":           "MOVLQSX AX,BX\nMOVQ BX,ret0+0(FP)\nRET",
		"partial extension source":             "MOVB $1,AX\nMOVWQSX AX,BX\nMOVQ BX,ret0+0(FP)\nRET",
		"word destination keeps unknown upper": "MOVB $1,AX\nMOVBWSX AX,BX\nMOVQ BX,ret0+0(FP)\nRET",
		"word high alias is SP":                "MOVW $1,AX\nMOVSWW AH,BX\nMOVQ BX,ret0+0(FP)\nRET",
		"byte REX alias is SP":                 "MOVB $1,AH\nMOVBQSX AH,BX\nMOVQ BX,ret0+0(FP)\nRET",
		"undefined explicit multiply input":    "MOVL $7,BX\nIMULL AX,BX\nMOVQ BX,ret0+0(FP)\nRET",
		"three operand source still undefined": "IMUL3Q $7,AX,BX\nMOVQ BX,ret0+0(FP)\nRET",
		"native load has no region":            "MOVLQSX (AX),BX\nMOVQ BX,ret0+0(FP)\nRET",
		"unknown AUTO byte":                    "MOVB $1,value-16(SP)\nMOVWQSX value-16(SP),BX\nMOVQ BX,ret0+0(FP)\nRET",
		"LEA is not numeric":                   "LEAQ value-16(SP),AX\nMOVQ AX,ret0+0(FP)\nRET",
	} {
		t.Run(name, func(t *testing.T) {
			file, sig, _ := x86ResultAUTOFixture(t, "amd64", "func Value() uint64", 32, body)
			if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("undefined/pointer/partial alias acquired numeric effect: %v", err)
			}
		})
	}
}
