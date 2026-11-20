package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// Keep the complete original function as an independent fixture, including
// its old unbound physical-SP spelling. The original 19-TEXT source and every
// signature in TestTranslate386InstructionFamilies remain unchanged.
const x86X87LegacyOriginalMathSource = `TEXT x87math(SB),NOSPLIT,$0-24
	FMOVD a+0(FP), F0
	FABS
	FMOVD b+8(FP), F0
	FUCOMI F0, F1
	FXCHD F0, F1
	FDIVD F1, F0
	FMULD F0, F0
	FLD1
	FADDDP F0, F1
	FSQRT
	FMULDP F0, F1
	FTST
	FSTSW AX
	FSTCW -2(SP)
	MOVW -2(SP), AX
	FLDCW -2(SP)
	FRNDINT
	FMOVDP F0, ret+16(FP)
	RET
`

const x86X87LegacyOriginalRoundingSource = `TEXT round(SB),NOSPLIT,$0-16
	FMOVD value+0(FP), F0
	FSTCW -2(SP)
	FLDCW -2(SP)
	FRNDINT
	FMOVVP F0, ret+8(FP)
	RET
`

func x86X87InstructionFamiliesBoundedCounterpart(t *testing.T, original string) string {
	t.Helper()
	if strings.Count(original, x86X87LegacyOriginalMathSource) != 1 {
		t.Fatal("bounded counterpart must retain the exact complete original x87math body")
	}
	bounded := strings.Replace(x86X87LegacyOriginalMathSource, "$0-24", "$4-24", 1)
	bounded = strings.ReplaceAll(bounded, "-2(SP)", "savedCW-2(SP)")
	if strings.Count(bounded, "savedCW-2(SP)") != 3 {
		t.Fatal("x87math scratch must retain all three original accesses")
	}
	return strings.Replace(original, x86X87LegacyOriginalMathSource, bounded, 1)
}

func x86X87LegacyBoundedRoundingSource(mode X87Mode) string {
	source := strings.Replace(x86X87LegacyOriginalRoundingSource, "$0-16", "$4-16", 1)
	source = strings.ReplaceAll(source, "-2(SP)", "control-2(SP)")
	if mode == X87Software {
		// This source, not a new Software API default, initializes the control
		// word before the first value load. Auto/Hardware retain real FNSTCW.
		source = strings.Replace(source, "\tFMOVD", "\tFINIT\n\tFMOVD", 1)
	}
	return source
}

type x86X87LegacyScratchCase struct {
	name, symbol, declaration, source, word, floatParameter string
	mode                                                    X87Mode
}

func x86X87LegacyScratchCases(t *testing.T) []x86X87LegacyScratchCase {
	t.Helper()
	var rows []x86X87LegacyScratchCase
	for _, mode := range []X87Mode{X87Auto, X87Hardware} {
		rows = append(rows, x86X87LegacyScratchCase{
			name: fmt.Sprintf("complete-x87math/mode%d", mode), symbol: "x87math",
			declaration: "func x87math(a,b float64) float64",
			source:      x86X87InstructionFamiliesBoundedCounterpart(t, x86X87LegacyOriginalMathSource),
			word:        "savedCW", floatParameter: "a", mode: mode,
		})
	}
	for _, mode := range []X87Mode{X87Auto, X87Hardware, X87Software} {
		rows = append(rows, x86X87LegacyScratchCase{
			name: fmt.Sprintf("complete-round/mode%d", mode), symbol: "round",
			declaration: "func round(value float64) int64",
			source:      x86X87LegacyBoundedRoundingSource(mode),
			word:        "control", floatParameter: "value", mode: mode,
		})
	}
	return rows
}

func TestX86X87LegacyBoundedScratchFixturesPreserveSourceRoles(t *testing.T) {
	for _, row := range x86X87LegacyScratchCases(t) {
		t.Run(row.name, func(t *testing.T) {
			file, err := Parse(ArchAMD64, row.source)
			if err != nil || len(file.Funcs) != 1 || file.Funcs[0].Sym != row.symbol || file.Funcs[0].FrameSize != 4 {
				t.Fatal("bounded counterpart lost its complete original TEXT", err)
			}
			original := x86X87LegacyOriginalRoundingSource
			if row.symbol == "x87math" {
				original = x86X87LegacyOriginalMathSource
			}
			restored := strings.Replace(row.source, "$4-", "$0-", 1)
			restored = strings.ReplaceAll(restored, row.word+"-2(SP)", "-2(SP)")
			if row.mode == X87Software {
				if !strings.Contains(restored, "\tFINIT\n\tFMOVD") || strings.Count(restored, "FINIT") != 1 {
					t.Fatal("Software control initialization must precede the first value load")
				}
				restored = strings.Replace(restored, "\tFINIT\n", "", 1)
			} else if strings.Contains(restored, "FINIT") {
				t.Fatal("Auto/Hardware acquired a synthetic control default")
			}
			if restored != original {
				t.Fatal("bounded counterpart changed an original non-scratch instruction")
			}
		})
	}
}

func TestX86X87LegacyBoundedScratchCompleteOriginalGoObjects(t *testing.T) {
	// Original objects establish actual Go source format, not safe native SP
	// backing, numerical results, portable proof or executed x87 semantics.
	rows := []struct{ name, source string }{
		{"original-complete-x87math", x86X87LegacyOriginalMathSource},
		{"bounded-complete-x87math", x86X87InstructionFamiliesBoundedCounterpart(t, x86X87LegacyOriginalMathSource)},
		{"original-complete-round", x86X87LegacyOriginalRoundingSource},
		{"bounded-round-real-control", x86X87LegacyBoundedRoundingSource(X87Auto)},
		{"bounded-round-explicit-Software-init", x86X87LegacyBoundedRoundingSource(X87Software)},
	}
	for _, target := range x86RawReturnTargets {
		if target.arch != "386" {
			continue
		}
		for _, row := range rows {
			t.Run(target.triple+"/"+row.name, func(t *testing.T) {
				x86LEAActualTargetGoObject(t, target.arch, target.triple,
					strings.ReplaceAll(row.source, ",NOSPLIT,", ",4,"))
			})
		}
	}
}

func TestX86X87LegacyBoundedScratchCompleteThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		if target.arch != "386" {
			continue
		}
		for _, row := range x86X87LegacyScratchCases(t) {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+row.name+"/"+api, func(t *testing.T) {
					ir, err := x86X87InitializedWordAPI(t, row.source, row.declaration,
						target.arch, target.triple, api, row.mode)
					if err != nil || ir == "" {
						t.Fatal("complete bounded original source remains unclosed", err)
					}
					x86X87LegacyScratchIRIdentity(t, ir, row)
				})
			}
		}
	}
}

func x86X87LegacyScratchIRIdentity(t *testing.T, ir string, row x86X87LegacyScratchCase) {
	t.Helper()
	context := llvm.NewContext()
	defer context.Dispose()
	module, err := parseIRModuleInContext(context, ir)
	if !module.IsNil() {
		defer module.Dispose()
	}
	if err != nil {
		t.Fatal("actual complete counterpart IR is malformed", err)
	}
	function := module.NamedFunction(row.symbol)
	parameters, result := 1, "i64"
	if row.symbol == "x87math" {
		parameters, result = 2, "double"
	}
	if function.IsNil() || function.FirstBasicBlock().IsNil() || function.ParamsCount() != parameters ||
		function.GlobalValueType().ReturnType().String() != result {
		t.Fatal("complete counterpart lost its real declared function identity")
	}
}

func x86X87LegacyScratchMutations(row x86X87LegacyScratchCase) map[string]string {
	cell := row.word + "-2(SP)"
	write := "\tFSTCW " + cell + "\n"
	return map[string]string{
		"zero-frame":        strings.Replace(row.source, "$4-", "$0-", 1),
		"physical-SP-role":  strings.ReplaceAll(row.source, cell, "-2(SP)"),
		"outside-frame":     strings.ReplaceAll(row.source, cell, row.word+"-6(SP)"),
		"missing-CW-write":  strings.Replace(row.source, write, "", 1),
		"partial-CW-write":  strings.Replace(row.source, write, "\tMOVB $127,"+cell+"\n", 1),
		"one-path-no-write": strings.Replace(row.source, write, "\tMOVL "+row.floatParameter+"+0(FP),AX\n\tTESTL AX,AX\n\tJE noControlWrite\n"+write+"noControlWrite:\n", 1),
		"CALL-SP-escape":    strings.Replace(row.source, write, "\tLEAL "+cell+",AX\n\tCALL ·escape(SB)\n"+write, 1),
	}
}

func TestX86X87LegacyBoundedScratchSingleMutationBoundaries(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		if target.arch != "386" {
			continue
		}
		for _, row := range x86X87LegacyScratchCases(t) {
			for name, source := range x86X87LegacyScratchMutations(row) {
				if source == row.source {
					t.Fatal("single-axis mutation did not change the complete source", row.name, name)
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(target.triple+"/"+row.name+"/"+name+"/"+api, func(t *testing.T) {
						ir, err := x86X87InitializedWordAPI(t, source, row.declaration,
							target.arch, target.triple, api, row.mode)
						if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatal("changed scratch source acquired unsupported storage or initialization", err)
						}
						// A first unrelated x87/CALL Context is not evidence that
						// this particular scratch/escape obligation was checked.
						t.Logf("observed first Context for %s: %v", name, err)
					})
				}
			}
		}
	}
}
