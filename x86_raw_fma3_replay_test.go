package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func x86RawFMA3RegisterProgram(row x86RawFMA3SourceCase, raw bool) string {
	first, second, destination := row.registers()
	var source strings.Builder
	source.WriteString("TEXT ·Value(SB),4,$0-4\n")
	for _, register := range []int{first, second, destination} {
		fmt.Fprintf(&source, "VPXORD Z%d,Z%d,Z%d\n", register, register, register)
	}
	source.WriteString("MOVL $85,AX\nKMOVW AX,K1\n")
	if raw {
		source.WriteString(x86RawDisplacementDirectives(row.code()))
	} else {
		source.WriteString(row.instruction() + "\n")
	}
	fmt.Fprintf(&source, "MOVL X%d,ret+0(FP)\nRET\n", destination)
	return source.String()
}

func x86RawFMA3OriginalFunction(t *testing.T, source, arch string) (Func, int) {
	t.Helper()
	file, err := normalizeX86RawFile(mustParseX86RawReturn(t, source), arch)
	if err != nil || len(file.Funcs) != 1 {
		t.Fatal("complete original raw FMA decode prerequisite", err)
	}
	function, ordinal := file.Funcs[0], -1
	for index, ins := range function.Instrs {
		base := strings.Split(string(ins.Op), ".")[0]
		if ins.x86SourceRaw != nil && (strings.HasPrefix(base, "VFM") || strings.HasPrefix(base, "VFNM")) {
			if ordinal >= 0 {
				t.Fatal("ambiguous original arithmetic instruction")
			}
			ordinal = index
		}
	}
	if ordinal < 0 || function.x86RawReplay == nil || function.x86RawReplay.validate(function, arch) != nil {
		t.Fatal("original whole FMA producer lost its exact sealed replay")
	}
	return function, ordinal
}

func TestX86RawFMA3WholeRegisterAndMemoryProducerReplay(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, memory := range []bool{false, true} {
			for _, row := range x86RawFMA3ObjectCases()[:60] {
				row.memory = memory
				source, declaration := x86RawFMA3InitializedSource(row, arch, "Value", "", false)
				named, _ := x86RawFMA3InitializedSource(row, arch, "Value", "named", false)
				if !memory {
					source, named = x86RawFMA3RegisterProgram(row, true), x86RawFMA3RegisterProgram(row, false)
					declaration = "func Value() uint32"
				}
				check := x86LegacyFloatReplayCheck(t, arch, named, declaration)
				t.Run(fmt.Sprintf("%s/%s/EVEX=%t/memory=%t/named", arch, row.op, row.evex, memory), func(t *testing.T) {
					function := mustParseX86RawReturn(t, named).Funcs[0]
					if function.x86RawReplay != nil || check(function) != nil {
						t.Fatal("legal independent named FMA producer lost its existing contract")
					}
				})
				for _, mutation := range []string{
					"valid", "origin", "origin-and-opcode", "origin-and-producer", "origin-and-spelling",
					"missing-replay", "source-spelling", "original-bytes", "decoded-snapshot",
					"normalized-snapshot", "header", "generation", "origin-operands", "vector-width",
				} {
					t.Run(fmt.Sprintf("%s/%s/EVEX=%t/memory=%t/%s", arch, row.op, row.evex, memory, mutation), func(t *testing.T) {
						original, ordinal := x86RawFMA3OriginalFunction(t, source, arch)
						candidate := original
						candidate.Instrs = cloneX86ReplayInstrs(original.Instrs)
						instruction := &candidate.Instrs[ordinal]
						if mutation == "origin" || strings.HasPrefix(mutation, "origin-and-") {
							instruction.x86SourceRaw = nil
						}
						switch mutation {
						case "origin-and-opcode":
							instruction.Op = "VFMSUB132PS"
							if row.op == string(instruction.Op) {
								instruction.Op = "VFMADD132PS"
							}
						case "origin-and-producer":
							candidate.Instrs[1].Raw += " changed"
						case "origin-and-spelling", "source-spelling":
							instruction.Raw += " changed"
						case "missing-replay":
							candidate.x86RawReplay = nil
						case "original-bytes", "decoded-snapshot", "normalized-snapshot":
							replay := *original.x86RawReplay
							switch mutation {
							case "original-bytes":
								replay.source = strings.Replace(replay.source, "BYTE $", "BYTE $1+", 1)
							case "decoded-snapshot":
								replay.decoded = cloneX86ReplayInstrs(replay.decoded)
								replay.decoded[ordinal].x86SourceRaw = nil
							case "normalized-snapshot":
								replay.normalized = cloneX86ReplayInstrs(replay.normalized)
								replay.normalized[ordinal].Raw += " changed"
							}
							candidate.x86RawReplay = &replay
						case "header":
							candidate.ArgSize++
						case "generation":
							instruction.x86Encoded = !instruction.x86Encoded
						case "origin-operands":
							instruction.x86SourceRaw.args[1].Reg = "X7"
						case "vector-width":
							instruction.x86VectorBytes = 7
						}
						err := check(candidate)
						if mutation == "valid" {
							if err != nil {
								t.Fatal("the original initialized whole raw FMA producer must succeed", err)
							}
						} else if !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("actual whole-Func consumer accepted an edited original FMA/producer identity", err)
						}
						if original.x86RawReplay.validate(original, arch) != nil {
							t.Fatal("mutating a clone corrupted its original independently sealed producer")
						}
					})
				}
			}
		}
	}
}

func TestX86RawFMA3OriginCannotSupplyMissingRegisterBytes(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86RawFMA3ObjectCases()[:60] {
			for _, missing := range []int{0, 1, 2} {
				t.Run(fmt.Sprintf("%s/%s/input=%d", arch, row.op, missing), func(t *testing.T) {
					source := x86RawFMA3RegisterProgram(row, true)
					line := fmt.Sprintf("VPXORD Z%d,Z%d,Z%d\n", missing, missing, missing)
					changed := strings.Replace(source, line, "", 1)
					if changed == source {
						t.Fatal("missing-input mutation did not remove its actual producer")
					}
					function, _ := x86RawFMA3OriginalFunction(t, changed, arch)
					check := x86LegacyFloatReplayCheck(t, arch, changed, "func Value() uint32")
					if err := check(function); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("an exact raw origin initialized an absent explicit or old-destination input", err)
					}
				})
			}
		}
	}
}

func TestX86RawFMA3DoesNotBorrowFP16OrStandaloneNamedPermission(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86RawFMA3ObjectCases()[:60] {
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				ins := x86RawMoveObservedInstruction(t, arch, row.code())
				state := x86FMA3ResultInputState()
				before := state.clone()
				if x86ScalarFPResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, before) {
					t.Fatal("standalone raw F32/F64 acquired ordinary named numerical permission")
				}
				if _, valid := x86RawFP16FMASourceForm(ins, arch); valid {
					t.Fatal("ordinary F32/F64 encoding borrowed the existing raw-only FP16 owner")
				}
			})
		}
		for opcode := range rawFP16FMAOps() {
			ins := x86RawMoveObservedInstruction(t, arch, x86FP16FMAResultEncoding(opcode, 0, false, false, false))
			if form, valid := x86RawFP16FMASourceForm(ins, arch); !valid || !form.spec.rawOnly {
				t.Fatal("ordinary raw FMA work revoked or relabelled the separate FP16 physical owner", opcode)
			}
		}
	}
}
