package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func x86LegacyFloatReplaySource(arch string, row x86RawLegacyFloatCompareOracle, memory bool, selector byte, raw bool) (string, string) {
	word, move, input := goWordSize(arch), "MOVQ", "X1"
	if arch == "386" {
		move = "MOVL"
	}
	if memory {
		input = "(BX)"
	}
	prefix := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s out+0(FP),DI\n%s left+%d(FP),AX\n%s right+%d(FP),BX\nMOVOU (AX),X0\nMOVOU (BX),X1\n",
		3*word, move, move, word, move, 2*word)
	operation := fmt.Sprintf("%s %s,X0,$%d\n", row.op, input, int8(selector))
	if raw {
		operation = x86RawDisplacementDirectives(row.code(memory, selector))
	}
	return prefix + operation + "MOVOU X0,(DI)\nRET\n", "func Value(out,left,right *byte)"
}

func x86LegacyFloatReplayConsumer(t *testing.T, arch string) func(Func) error {
	t.Helper()
	source, declaration := x86LegacyFloatReplaySource(arch, x86RawLegacyFloatCompareOracles[0], false, 0, false)
	return x86LegacyFloatReplayCheck(t, arch, source, declaration)
}

func x86LegacyFloatReplayCheck(t *testing.T, arch, source, declaration string) func(Func) error {
	t.Helper()
	pkg := mustGoPackage(t, "comparereplay", "package comparereplay\n"+declaration)
	resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
	signatures, err := goSigsForAsmFile(pkg, mustParseX86RawReturn(t, source), resolve, arch, nil, nil, nil)
	if err != nil {
		t.Fatal("actual original declaration/FP-layout prerequisite", err)
	}
	sig, found := signatures["Value"]
	if !found {
		t.Fatal("actual original compare declaration disappeared")
	}
	return func(function Func) error {
		consumer := amd64Ctx{fpScalarSource: function, sig: sig, fpSourceSig: sig,
			goarch: arch, targetTriple: x86AddressMemoryTargets(arch)[0]}
		return consumer.checkLoweredScalarFPResultInitialization()
	}
}

func x86LegacyFloatReplayOriginal(t *testing.T, arch, source string) (Func, int) {
	t.Helper()
	file, err := normalizeX86RawFile(mustParseX86RawReturn(t, source), arch)
	if err != nil {
		t.Fatal("original complete compare decoding prerequisite", err)
	}
	function, ordinal := file.Funcs[0], -1
	for index, ins := range function.Instrs {
		if x86RawLegacyFloatCompareSource(ins, arch) {
			if ordinal >= 0 {
				t.Fatal("ambiguous original raw compare instruction")
			}
			ordinal = index
		}
	}
	if ordinal < 0 || function.x86RawReplay == nil || function.x86RawReplay.validate(function, arch) != nil {
		t.Fatal("complete original source lost its immutable compare replay")
	}
	return function, ordinal
}

func TestX86RawLegacyFloatingCompareReplayCompleteOriginalGoBytes(t *testing.T) {
	x86RawLegacyFloatCompareOriginalProgramsUnchanged(t)
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			var source strings.Builder
			var expected []byte
			for _, row := range x86RawLegacyFloatCompareOracles {
				for _, memory := range []bool{false, true} {
					input := "X1"
					if memory {
						input = "(BX)"
					}
					for selector := 0; selector < 256; selector++ {
						fmt.Fprintf(&source, "%s %s,X0,$%d\n", row.op, input, int8(selector))
						expected = append(expected, row.code(memory, byte(selector))...)
					}
				}
			}
			actual, pcs := x86NumericalBoundaryGoBytes(t, arch, source.String()+"RET")
			expected = append(expected, 0xc3)
			if len(pcs) != 2049 || !bytes.Equal(actual, expected) {
				t.Fatal("actual Go bytes differ from the independent four-prefix/all256-selector register/memory table", len(pcs))
			}
		})
	}
}

func TestX86RawLegacyFloatingCompareOriginOnlyDirectNamedControl(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86RawLegacyFloatCompareOracles {
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				for _, memory := range []bool{false, true} {
					for selector := 0; selector < 256; selector++ {
						original := x86RawMoveObservedInstruction(t, arch, row.code(memory, byte(selector)))
						if original.x86Encoded || original.x86SourceRaw == nil {
							t.Fatal("legacy decoder generation prerequisite changed")
						}
						changed := cloneX86ReplayInstrs([]Instr{original})[0]
						changed.x86SourceRaw = nil
						if x86RawLegacyFloatCompareSource(changed, arch) || !x86ResultNamedPredicateInstruction(changed) {
							t.Fatal("an erased raw origin is not a raw witness and can have the named instruction contract")
						}
						named := x86ScalarLaneInstruction(t, fmt.Sprintf("%s %s,X0,$%d", row.op, changed.Args[0], int8(selector)))
						state, control := x86RawLegacyFloatCompareState(), x86RawLegacyFloatCompareState()
						accepted, known := x86ResultFloatCompareStep(changed, &state, nil, arch, true)
						valid, recognized := x86ResultFloatCompareStep(named, &control, nil, arch, true)
						if !accepted || !known || !valid || !recognized || !reflect.DeepEqual(state, control) {
							t.Fatal("direct origin-only mutation must not be mislabeled a missing-input rejection or forbid legal named instructions", memory, selector)
						}
					}
				}
			})
		}
	}
}

func TestX86RawLegacyFloatingCompareOriginOnlyWholeReplayAllSelectors(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		check := x86LegacyFloatReplayConsumer(t, arch)
		for _, row := range x86RawLegacyFloatCompareOracles {
			for _, memory := range []bool{false, true} {
				for selector := 0; selector < 256; selector++ {
					t.Run(fmt.Sprintf("%s/%s/memory=%t/selector=%03d", arch, row.op, memory, selector), func(t *testing.T) {
						source, _ := x86LegacyFloatReplaySource(arch, row, memory, byte(selector), true)
						function, ordinal := x86LegacyFloatReplayOriginal(t, arch, source)
						if err := check(function); err != nil {
							t.Fatal("valid initialized original source failed before any identity mutation", err)
						}
						namedSource, _ := x86LegacyFloatReplaySource(arch, row, memory, byte(selector), false)
						named := mustParseX86RawReturn(t, namedSource).Funcs[0]
						if named.x86RawReplay != nil || check(named) != nil {
							t.Fatal("ordinary complete named source control must retain its original domain")
						}
						changed := function
						changed.Instrs = cloneX86ReplayInstrs(function.Instrs)
						changed.Instrs[ordinal].x86SourceRaw = nil // Do not also change generation.
						if err := check(changed); !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("actual whole-Func consumer accepted an erased immutable original compare origin", err)
						}
						if function.x86RawReplay.validate(function, arch) != nil {
							t.Fatal("mutating a clone corrupted its independently retained original source")
						}
					})
				}
			}
		}
	}
}

func TestX86RawLegacyFloatingCompareOriginalReplayConsumerMutationBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		check := x86LegacyFloatReplayConsumer(t, arch)
		for _, row := range x86RawLegacyFloatCompareOracles {
			for _, memory := range []bool{false, true} {
				for _, selector := range []byte{0, 128, 255} {
					source, _ := x86LegacyFloatReplaySource(arch, row, memory, selector, true)
					function, ordinal := x86LegacyFloatReplayOriginal(t, arch, source)
					for _, mutation := range []string{"none", "origin", "origin-and-selector", "origin-and-opcode", "origin-and-producer", "origin-and-spelling",
						"missing-replay", "source-spelling", "original-bytes", "decoded-snapshot", "normalized-snapshot", "header", "generation", "snapshot", "address-width", "numerical-read"} {
						t.Run(fmt.Sprintf("%s/%s/memory=%t/selector=%03d/%s", arch, row.op, memory, selector, mutation), func(t *testing.T) {
							candidate := function
							candidate.Instrs = cloneX86ReplayInstrs(function.Instrs)
							ins := &candidate.Instrs[ordinal]
							if mutation == "origin" || strings.HasPrefix(mutation, "origin-and-") {
								ins.x86SourceRaw = nil
							}
							switch mutation {
							case "origin-and-selector":
								ins.Args[2].Imm = int64(int8(ins.Args[2].Imm + 1))
							case "origin-and-opcode":
								ins.Op = "CMPPS"
								if row.op == "CMPPS" {
									ins.Op = "CMPPD"
								}
							case "origin-and-producer":
								candidate.Instrs[ordinal-1].Op = "VMOVDQU"
							case "origin-and-spelling", "source-spelling":
								ins.Raw += " changed"
							case "missing-replay":
								candidate.x86RawReplay = nil
							case "original-bytes":
								replay := *function.x86RawReplay
								replay.source = strings.Replace(replay.source, "BYTE $", "BYTE $1+", 1)
								candidate.x86RawReplay = &replay
							case "decoded-snapshot", "normalized-snapshot":
								replay := *function.x86RawReplay
								if mutation == "decoded-snapshot" {
									replay.decoded = cloneX86ReplayInstrs(replay.decoded)
									replay.decoded[ordinal].x86SourceRaw = nil
								} else {
									replay.normalized = cloneX86ReplayInstrs(replay.normalized)
									replay.normalized[ordinal].x86SourceRaw = nil
								}
								candidate.x86RawReplay = &replay
							case "header":
								candidate.ArgSize += int64(goWordSize(arch))
							case "generation":
								ins.x86Encoded = true
							case "snapshot":
								ins.x86SourceRaw.legacyFloatCompare = x86RawLegacyFloatCompareIdentity{}
							case "address-width":
								ins.x86AddressBits = 16
							case "numerical-read":
								ins.x86NumericalRead = new(x86NumericalReadCertificate)
							}
							err := check(candidate)
							if mutation == "none" && err != nil || mutation != "none" && !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("actual original-source consumer lost its bounded complete replay contract", mutation, err)
							}
							if function.x86RawReplay.validate(function, arch) != nil {
								t.Fatal("a private clone mutation changed the retained original source")
							}
						})
					}
					for _, spelling := range []bool{false, true} {
						t.Run(fmt.Sprintf("%s/%s/memory=%t/selector=%03d/raw=%t/missing-input", arch, row.op, memory, selector, spelling), func(t *testing.T) {
							original, _ := x86LegacyFloatReplaySource(arch, row, memory, selector, spelling)
							missing := strings.Replace(original, "MOVOU (AX),X0\n", "", 1)
							function := mustParseX86RawReturn(t, missing).Funcs[0]
							if spelling {
								function, _ = x86LegacyFloatReplayOriginal(t, arch, missing)
							}
							if err := check(function); !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("an original replay or named spelling manufactured missing input bytes", err)
							}
						})
					}
				}
			}
		}
	}
}
