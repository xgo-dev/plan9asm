package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type x86X87IntegerInputRow struct {
	name, instruction, inputType string
	load, pop                    bool
}

// Independent complete nine directions. The initializer and scratch are source
// text, not synthesized initial F0/CW facts or a new source/storage producer.
var x86X87IntegerInputRows = []x86X87IntegerInputRow{
	{"load-W", "FMOVW input+0(FP),F0", "int16", true, false},
	{"store-W", "FMOVW F0,converted-8(SP)", "int64", false, false},
	{"store-WP", "FMOVWP F0,converted-8(SP)", "int64", false, true},
	{"load-L", "FMOVL input+0(FP),F0", "int32", true, false},
	{"store-L", "FMOVL F0,converted-8(SP)", "int64", false, false},
	{"store-LP", "FMOVLP F0,converted-8(SP)", "int64", false, true},
	{"load-V", "FMOVV input+0(FP),F0", "int64", true, false},
	{"store-VP", "FMOVVP F0,converted-8(SP)", "int64", false, true},
	{"round", "FRNDINT", "float64", false, false},
}

type x86X87IntegerInputCase struct {
	name, body string
	good       bool
}

func x86X87IntegerInputCases(row x86X87IntegerInputRow) []x86X87IntegerInputCase {
	preload, discard := "FLD1\n", "FMOVDP F0,F0\n"
	if row.load {
		preload = ""
	}
	if row.pop {
		discard = ""
	}
	core := preload + row.instruction + "\n" + discard
	unknownAUTO := "FINIT\nFMOVD unread-16(SP),F0\n" + row.instruction + "\n" + discard
	bareSP := "FINIT\nMOVL $0,-16(SP)\nMOVL $0,-12(SP)\nFMOVD -16(SP),F0\n" + row.instruction + "\n" + discard
	if row.load {
		unknownAUTO = "FINIT\n" + strings.Replace(row.instruction, "input+0(FP)", "unread-16(SP)", 1) + "\n" + discard
		bareSP = "FINIT\nMOVL $0,-16(SP)\nMOVL $0,-12(SP)\n" +
			strings.Replace(row.instruction, "input+0(FP)", "-16(SP)", 1) + "\n" + discard
	}
	cases := []x86X87IntegerInputCase{
		{"initialized-balanced", "FINIT\n" + core, true},
		{"uninitialized-named-AUTO", unknownAUTO, false},
		{"bare-SP-not-AUTO", bareSP, false},
		// FINIT after the conversion empties the stack, so this negative
		// cannot be explained only by an unbalanced stack at RET. The ninth
		// independently authored push is itself outside the value domain.
		{"ninth-push", "FINIT\n" + strings.Repeat("FLD1\n", 9) + core + "FINIT\n", false},
	}
	if !row.load {
		cases = append(cases,
			x86X87IntegerInputCase{"unknown-F0", "FINIT\n" + row.instruction + "\n" + discard, false},
			// A fractional value makes RC an actual input. This does not
			// depend on a default virtual CW, integer-load range or a private
			// alloca's initial contents. Only Software is tested here.
			x86X87IntegerInputCase{"unknown-CW", "FMOVD $(2.5),F0\n" + row.instruction + "\n" + discard, false},
		)
	}
	return cases
}

func x86X87IntegerInputSource(t *testing.T, arch, declaration, body string, independentAUTO bool, resultWrite string) string {
	t.Helper()
	_, _, sig, _ := x86ResultInitializationFixture(t, arch, declaration, "RET")
	var extent int64
	for _, slots := range [][]FrameSlot{sig.Frame.Params, sig.Frame.Results} {
		for _, slot := range slots {
			end := slot.Offset + x86FrameScalarBytes(slot.Type, arch)
			if end > extent {
				extent = end
			}
		}
	}
	if len(sig.Frame.Results) == 0 {
		if sig.Ret != Void || resultWrite != "" {
			t.Fatal("Void fixture acquired a fabricated result slot or store")
		}
	} else {
		if sig.Ret != I32 || len(sig.Frame.Results) != 1 || sig.Frame.Results[0].Type != I32 {
			t.Fatal("independent result fixture lost its actual I32 declaration", sig)
		}
		destination := fmt.Sprintf("ret+%d(FP)", sig.Frame.Results[0].Offset)
		switch resultWrite {
		case "complete":
			if independentAUTO {
				body += "MOVL $7,result-4(SP)\nMOVL result-4(SP),AX\nMOVL AX," + destination + "\n"
			} else {
				body += "MOVL $7," + destination + "\n"
			}
		case "partial":
			body += "MOVW $7," + destination + "\n"
		case "missing":
		default:
			t.Fatal("unknown result boundary", resultWrite)
		}
	}
	source := fmt.Sprintf("TEXT ·Value(SB),4,$16-%d\n%sRET\n", extent, body)
	file, err := Parse(ArchAMD64, source)
	if err != nil || len(file.Funcs) != 1 || file.Funcs[0].FrameSize != 16 || file.Funcs[0].ArgSize != extent {
		t.Fatal("whole input-obligation fixture lost its complete original source/header", err)
	}
	return source
}

func x86X87CheckIntegerInputCase(t *testing.T, source, declaration, arch, triple, api string, good bool) {
	t.Helper()
	ir, err := x86X87InitializedWordAPI(t, source, declaration, arch, triple, api, X87Software)
	if good {
		if err != nil || ir == "" {
			t.Fatal("initialized/balanced source did not retain its old independent storage role", err)
		}
	} else if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
		t.Fatalf("integer/round source obligation was bypassed: output=%t error=%v\ncomplete source:\n%s", ir != "", err, source)
	} else {
		t.Logf("actual first Context (not an inferred later boundary): %v", err)
	}
}

func TestX86X87IntegerRoundVoidInputsNeedWholeProof(t *testing.T) {
	if len(x86X87IntegerInputRows) != 9 {
		t.Fatal("complete seven-name/nine-direction input denominator changed")
	}
	for _, target := range x86RawReturnTargets {
		for _, profile := range []struct{ name, declarationFormat string }{
			{"Void", "func Value(input %s)"},
			{"Void-unused-bool", "func Value(input %s,gate bool)"},
		} {
			for _, row := range x86X87IntegerInputRows {
				declaration := fmt.Sprintf(profile.declarationFormat, row.inputType)
				for _, test := range x86X87IntegerInputCases(row) {
					source := x86X87IntegerInputSource(t, target.arch, declaration, test.body, false, "")
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(target.triple+"/"+profile.name+"/"+row.name+"/"+test.name+"/"+api, func(t *testing.T) {
							x86X87CheckIntegerInputCase(t, source, declaration, target.arch, target.triple, api, test.good)
						})
					}
				}
			}
		}
	}
	// Source/effect observation only: no backend, native execution or permission
	// to use an incoming native pointer or write caller storage is supplied.
}

func TestX86X87IntegerRoundIndependentStorageCannotBypassInputs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, profile := range []struct {
			name, declarationFormat string
			independentAUTO         bool
		}{
			{"natural-I32-result", "func Value(input %s) uint32", false},
			{"unused-bool-and-AUTO-result", "func Value(input %s,gate bool) uint32", true},
		} {
			for _, row := range x86X87IntegerInputRows {
				declaration := fmt.Sprintf(profile.declarationFormat, row.inputType)
				cases := x86X87IntegerInputCases(row)
				// Result stores are independently complete for every input
				// negative above. These two controls instead hold all inputs
				// valid and remove only the result's required initialized bytes.
				cases = append(cases,
					x86X87IntegerInputCase{"missing-result", cases[0].body, false},
					x86X87IntegerInputCase{"partial-result", cases[0].body, false},
				)
				for _, test := range cases {
					resultWrite := "complete"
					if test.name == "missing-result" {
						resultWrite = "missing"
					} else if test.name == "partial-result" {
						resultWrite = "partial"
					}
					source := x86X87IntegerInputSource(t, target.arch, declaration, test.body, profile.independentAUTO, resultWrite)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(target.triple+"/"+profile.name+"/"+row.name+"/"+test.name+"/"+api, func(t *testing.T) {
							x86X87CheckIntegerInputCase(t, source, declaration, target.arch, target.triple, api, test.good)
						})
					}
				}
			}
		}
	}
}
