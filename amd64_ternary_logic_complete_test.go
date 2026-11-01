package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86TernaryTypedEffectsRetainAllTruthTableDependencies(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, opcode := range []string{"VPTERNLOGD", "VPTERNLOGQ"} {
			for _, bank := range []string{"X", "Y", "Z"} {
				for _, aliases := range [][3]int{{2, 1, 0}, {2, 2, 0}, {2, 1, 2}, {2, 1, 1}, {2, 2, 2}} {
					for selector := 0; selector < 256; selector++ {
						for _, mode := range []string{"", "merge", "zero"} {
							suffix, mask := "", ""
							if mode != "" {
								mask = ",K7"
							}
							if mode == "zero" {
								suffix = ".Z"
							}
							row := fmt.Sprintf("%s%s $%d,%s%d,%s%d%s,%s%d", opcode, suffix, selector, bank, aliases[2], bank, aliases[1], mask, bank, aliases[0])
							ins := x86ScalarLaneInstruction(t, row)
							if arch == "386" {
								ins.x86Encoded = true // Physical grammar only, never an origin or entry certificate.
								ins.x86VectorBytes = amd64VectorByteWidth(ins.Args[len(ins.Args)-1].Reg)
							}
							effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
							if !known || err != nil || !effect.requiresResultProof {
								t.Fatal("complete selector lost its typed effect", arch, row, known, err)
							}
							reads := map[int]bool{}
							for _, operand := range effect.operands {
								if register, valid := amd64VectorRegisterIndex(operand.operand.Reg, amd64VectorByteWidth(operand.operand.Reg)); valid && operand.read {
									reads[register] = true
								}
							}
							for register := 0; register < 3; register++ {
								want := !ternaryResultBitKnown(selector, aliases, register) || mode == "merge" && aliases[0] == register
								if reads[register] != want {
									t.Fatal("typed effect invented or lost a physical Boolean dependency", arch, row, register, reads[register], want)
								}
							}
							if effect.flagsRead|effect.flagsDefined|effect.flagsKilled != 0 {
								t.Fatal("Boolean truth table changed FLAGS", row, effect)
							}
						}
					}
				}
			}
		}
	}
}

func x86TernaryNativeOracleState(arch string, width int) x86ResultState {
	state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward, masks: [8]bool{7: true}}
	for register := 0; register < 3; register++ {
		state.writeVector(register, 64, 0xa5a55a5affff0000|x86CallerVectorByteMask(int64(width)), true)
	}
	state.gp[0], state.gp[1], state.pointerGP[0] = 0xff, 0xff, true
	if arch == "386" {
		state.gp[0], state.gp[1] = 0x0f, 0x0f
	}
	return state
}

func TestX86TernaryRawIdentityMemoryAndIndependentState(t *testing.T) {
	rows := x86TernaryCompleteOracleRows()
	raw := x86TernaryOriginalRawRows(t, rows)
	var source strings.Builder
	for index, row := range raw {
		fmt.Fprintf(&source, "TEXT F%d(SB),4,$0-0\n%s\nRET\n", index, row)
	}
	for _, arch := range []string{"386", "amd64"} {
		file, err := normalizeX86RawFile(mustParseX86RawReturn(t, source.String()), arch)
		if err != nil || len(file.Funcs) != 54 {
			t.Fatal("complete physical ternary source normalization failed", arch, err)
		}
		for index, row := range rows {
			t.Run(arch+"/"+row.row, func(t *testing.T) {
				function := file.Funcs[index]
				ins := function.Instrs[1]
				if !x86RawTernaryLogicSource(ins, arch) {
					t.Fatal("actual mode/selector/vector fields lost immutable source identity")
				}
				initial := x86TernaryNativeOracleState(arch, row.width)
				state := initial.clone()
				if x86ResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, initial) {
					t.Fatal("standalone query borrowed a paired raw/native permission")
				}
				if accepted, known := x86ResultTernaryLogicContinuationStep(ins, &state, nil, arch, true); !accepted || !known {
					t.Fatal("complete initialized exact raw inputs failed their paired E4 transfer")
				}
				want := initial.clone()
				want.writeVector(2, row.width, x86CallerVectorByteMask(int64(row.width)), false)
				if !reflect.DeepEqual(state, want) {
					t.Fatal("ternary transfer changed independent registers, FLAGS, DF, pointers or upper aliases")
				}
				addresses := [16]bool{0: true, 3: true}
				if !x86ResultPreservesPrivateStorage(ins, arch) ||
					x86ResultDirectionAfterSource(ins, initial.direction, arch) != initial.direction ||
					x86ResultCallerAddressesAfter(ins, addresses, nil, arch) != addresses {
					t.Fatal("exact raw vector effect lost existing private/DF/caller identity facts")
				}
				for register := 0; register < 3; register++ {
					if row.memory && register == 0 {
						continue // Its physical operand is a volatile memory read, not vector0.
					}
					for missing := 0; missing < 64; missing++ {
						before := initial.clone()
						before.writeVector(register, 64, before.vectorBytes(register)&^(uint64(1)<<uint(missing)), true)
						state := before.clone()
						if accepted, known := x86ResultTernaryLogicContinuationStep(ins, &state, nil, arch, true); !accepted || !known {
							t.Fatal("nontrapping unknown Boolean input must propagate, never become an invented initialized value")
						}
						output := x86CallerVectorByteMask(int64(row.width))
						if missing < row.width {
							output &^= uint64(1) << uint(missing) // Selector150 consumes A XOR B XOR C.
						}
						want := before.clone()
						want.writeVector(2, row.width, output, false)
						if !reflect.DeepEqual(state, want) {
							t.Fatal("unknown byte or unrelated storage was silently initialized", register, missing)
						}
					}
				}
				for _, mutate := range []func(*Instr){
					func(ins *Instr) { ins.Op = "UNKNOWN" },
					func(ins *Instr) { ins.Args[0].Imm ^= 1 },
					func(ins *Instr) { ins.Args[2].Reg = "X7" },
					func(ins *Instr) { ins.Args[len(ins.Args)-1].Reg = "X7" },
					func(ins *Instr) { ins.x86Encoded = false },
					func(ins *Instr) { ins.x86VectorBytes++ },
					func(ins *Instr) { ins.x86AddressBits = 32 },
					func(ins *Instr) { ins.x86SegmentPrefix = 0x64 },
					func(ins *Instr) { ins.x86UnboundAddressOverride = true },
					func(ins *Instr) { ins.x86SourceRaw = nil },
					func(ins *Instr) {
						origin := *ins.x86SourceRaw
						origin.ternaryLogic = x86RawTernaryLogicIdentity{}
						ins.x86SourceRaw = &origin
					},
				} {
					changed := cloneX86ReplayInstrs([]Instr{ins})[0]
					mutate(&changed)
					state := initial.clone()
					if x86RawTernaryLogicSource(changed, arch) {
						t.Fatal("edited selector/shape/mode borrowed original raw identity")
					}
					if accepted, _ := x86ResultTernaryLogicContinuationStep(changed, &state, nil, arch, true); accepted || !reflect.DeepEqual(state, initial) {
						t.Fatal("rejected raw identity mutated numerical or native state")
					}
				}
				other := "386"
				if arch == "386" {
					other = "amd64"
				}
				if x86RawTernaryLogicSource(ins, other) {
					t.Fatal("physical ternary origin borrowed another creation mode")
				}
				clone := cloneX86ReplayInstrs(function.Instrs)
				if clone[1].x86SourceRaw == ins.x86SourceRaw || !x86RawTernaryLogicSource(clone[1], arch) {
					t.Fatal("immutable replay clone lost or shared mutable physical metadata")
				}
				if row.mask >= 0 {
					state := initial.clone()
					state.masks[7] = false
					before := state.clone()
					if accepted, _ := x86ResultTernaryLogicContinuationStep(ins, &state, nil, arch, true); accepted || !reflect.DeepEqual(state, before) {
						t.Fatal("unknown K input borrowed constant-selector or dead-result permission")
					}
				}
				if row.memory {
					state := initial.clone()
					state.pointerGP[0] = false
					before := state.clone()
					if accepted, _ := x86ResultTernaryLogicContinuationStep(ins, &state, nil, arch, true); accepted || !reflect.DeepEqual(state, before) {
						t.Fatal("a numerical address became an incoming pointer")
					}
				}
			})
		}
	}
}

func x86TernaryInitializedFixture(name, arch, instruction string) (string, string) {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	return fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s p+0(FP),AX\n%s p+0(FP),BX\n"+
			"MOVL $1,CX\nMOVL $85,DX\nKMOVD DX,K7\nVPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\n"+
			"STC\n%s\nVMOVDQU64 Z2,(BX)\nSETCS 64(BX)\nRET\n", name, word, move, move, instruction),
		"func " + name + "(p *byte)\n"
}

func TestX86TernaryCompleteInitializedNamedRawFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete ternary initialized objects require LLVM22")
	}
	rows := x86TernaryCompleteOracleRows()
	raw := x86TernaryOriginalRawRows(t, rows)
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			spellings := []string{"raw"}
			if target.arch == "amd64" {
				spellings = append(spellings, "named")
			}
			for _, spelling := range spellings {
				t.Run(spelling, func(t *testing.T) {
					var source, declarations strings.Builder
					for index, row := range rows {
						instruction := row.row
						if spelling == "raw" {
							instruction = raw[index]
						}
						body, declaration := x86TernaryInitializedFixture(fmt.Sprintf("Ternary%d", index), target.arch, instruction)
						source.WriteString(body)
						declarations.WriteString(declaration)
					}
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
							if err != nil || ir == "" {
								t.Fatal("complete initialized ternary public program failed", err)
							}
							optimized := x86DwordProductIROptimize(t, ir)
							for _, pipeline := range []struct{ name, ir, backend string }{
								{"backend_O0", ir, "-O0"}, {"backend_O2", ir, "-O2"}, {"IR_O2_backend_O2", optimized, "-O2"},
							} {
								t.Run(pipeline.name, func(t *testing.T) {
									x86PackedStringCompileObject(t, llc, target.triple, pipeline.ir, pipeline.backend)
								})
							}
						})
					}
				})
			}
		})
	}
	t.Log("432 complete initialized source kernels, all3 APIs and3 LLVM22 object paths; not original AVX512 execution")
}

func TestX86TernaryVoidRetainsMaskAndNativeAddressObligations(t *testing.T) {
	for _, row := range x86TernaryCompleteOracleRows() {
		if !row.memory && row.mask < 0 {
			continue // Nontrapping dead register results may remain unknown.
		}
		for _, unusedBool := range []bool{false, true} {
			extent, declaration := 0, "func Missing()"
			if unusedBool {
				extent, declaration = 1, "func Missing(unused bool)"
			}
			source := fmt.Sprintf("TEXT ·Missing(SB),4,$0-%d\n%s\nRET\n", extent, strings.Replace(row.row, "$150", "$0", 1))
			for _, api := range []string{"text", "module", "Go"} {
				if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("constant selector/Void/unused bool invented a mask or native address", row.row, unusedBool, api, err)
				}
			}
		}
	}
}
