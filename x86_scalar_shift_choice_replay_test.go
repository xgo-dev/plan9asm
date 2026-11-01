package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestX86ScalarShiftArchitecturalChoiceOriginalReplayMutationBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		rows := x86ShiftChoiceCases(arch)
		code := x86ShiftChoiceOriginalBytes(t, arch, rows)
		first, declaration := x86ShiftChoiceSource(arch, rows[0].text, code[0], "", true)
		pkg := mustGoPackage(t, "scalarreplay", "package scalarreplay\n"+declaration)
		resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
		signatures, err := goSigsForAsmFile(pkg, mustParseX86RawReturn(t, first), resolve, arch, nil, nil, nil)
		if err != nil {
			t.Fatal("actual typed declaration/FP layout prerequisite", err)
		}
		sig, present := signatures["Choice"]
		if !present {
			t.Fatal("actual original function declaration disappeared")
		}
		check := func(function Func) error {
			consumer := amd64Ctx{fpScalarSource: function, sig: sig, fpSourceSig: sig,
				goarch: arch, targetTriple: x86AddressMemoryTargets(arch)[0]}
			return consumer.checkLoweredScalarFPResultInitialization()
		}
		for index, row := range rows {
			if !row.flagsChoice {
				continue // BMI2 retains its separate complete continuation owner.
			}
			t.Run(arch+"/"+row.text, func(t *testing.T) {
				source, _ := x86ShiftChoiceSource(arch, row.text, code[index], "", true)
				file, err := normalizeX86RawFile(mustParseX86RawReturn(t, source), arch)
				if err != nil {
					t.Fatal("original raw producer/whole-source replay prerequisite", err)
				}
				function := file.Funcs[0]
				ordinal := -1
				for at, instruction := range function.Instrs {
					if x86RawLegacyScalarShiftSource(instruction, arch) {
						if ordinal >= 0 {
							t.Fatal("ambiguous original raw scalar producer")
						}
						ordinal = at
					}
				}
				if ordinal < 0 || function.x86RawReplay == nil || function.x86RawReplay.validate(function, arch) != nil {
					t.Fatal("original decoded producer lost its immutable whole-source replay")
				}
				for _, mutation := range []string{"none", "origin", "opcode", "operand", "source-operand", "vector", "address", "override", "segment", "literal", "return", "reader", "missing replay", "source spelling", "original bytes", "decoded snapshot"} {
					t.Run(mutation, func(t *testing.T) {
						candidate := function
						candidate.Instrs = cloneX86ReplayInstrs(function.Instrs)
						switch mutation {
						case "missing replay":
							candidate.x86RawReplay = nil
						case "source spelling":
							candidate.Instrs[ordinal].Raw += " changed"
						case "original bytes":
							replay := *function.x86RawReplay
							replay.source = strings.Replace(replay.source, "BYTE $", "BYTE $1+", 1)
							candidate.x86RawReplay = &replay
						case "decoded snapshot":
							replay := *function.x86RawReplay
							replay.decoded = cloneX86ReplayInstrs(replay.decoded)
							replay.decoded[ordinal].x86SourceRaw = nil
							candidate.x86RawReplay = &replay
						default:
							candidate.Instrs[ordinal] = x86ShiftChoiceMutatedOrigin(candidate.Instrs[ordinal], mutation)
						}
						err := check(candidate)
						if mutation == "none" && err != nil || mutation != "none" && !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("actual paired consumer lost original source identity or rejected initialized bytes", mutation, err)
						}
						if function.x86RawReplay.validate(function, arch) != nil {
							t.Fatal("a mutation changed the independently retained original replay")
						}
					})
				}
				for _, control := range []string{"named", "missing bytes"} {
					t.Run(control, func(t *testing.T) {
						input := ""
						if control == "missing bytes" {
							input = "missing x"
						}
						source, _ := x86ShiftChoiceSource(arch, row.text, nil, input, true)
						named := mustParseX86RawReturn(t, source).Funcs[0]
						if named.x86RawReplay != nil {
							t.Fatal("ordinary named source unexpectedly carries raw replay")
						}
						err := check(named)
						if control == "named" && err != nil || control == "missing bytes" && !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("named grammar or missing-input boundary changed", control, err)
						}
					})
				}
			})
		}
	}
}
