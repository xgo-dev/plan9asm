package plan9asm

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestGoAMD64FixedLocalCountedLoopAliasesAndUpdates(t *testing.T) {
	var original strings.Builder
	count := 0
	aliases := x86ConditionalBranchAliasOracle()
	var names []string
	for alias := range aliases {
		names = append(names, alias)
	}
	sort.Strings(names)
	for _, alias := range names {
		canonical := aliases[alias]
		if got := x86BranchCondition(Op(alias)); got != strings.TrimPrefix(canonical, "J") {
			t.Fatalf("complete branch condition %s = %s, want %s", alias, got, canonical)
		}
		if canonical != "JCS" && canonical != "JHI" {
			continue
		}
		for _, register := range strings.Fields("AX BX CX DX DI SI BP R8 R9 R10 R11 R12 R13 R14 R15") {
			for variant := 0; variant < 3; variant++ {
				first, bound, delta, operation := 0, 24, 8, "ADDQ"
				if canonical == "JHI" {
					first, bound, operation = 24, 0, "SUBQ"
				}
				if variant == 1 {
					delta = -delta
					if operation == "ADDQ" {
						operation = "SUBQ"
					} else {
						operation = "ADDQ"
					}
				}
				update, scale := fmt.Sprintf("%s $%d,%s", operation, delta, register), 1
				if variant == 2 {
					first, bound, operation, scale = 0, 3, "INCQ", 8
					if canonical == "JHI" {
						first, bound, operation = 3, 0, "DECQ"
					}
					update = operation + " " + register
				}
				body := fmt.Sprintf("MOVQ $%d,%s\nloop:\nMOVQ AX,16(SP)(%s*%d)\n%s\nCMPQ %s,$%d\n%s loop\nMOVQ 24(SP),AX",
					first, register, register, scale, update, register, bound, alias)
				fn, sig, source := fixedLocalCountedLoopFixture(t, body)
				original.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", count), 1))
				count++
				t.Run(alias+"/"+register+"/"+operation, func(t *testing.T) {
					if _, err := proveX86FixedLocal(fn, sig); err != nil {
						t.Fatal("canonical unsigned condition or signed update spelling was lost", err)
					}
				})
			}
		}
	}
	if count != 360 {
		t.Fatal("eight unsigned aliases by 15 GP registers and three update spellings changed", count)
	}
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
}

func TestGoAMD64FixedLocalCountedLoopCertificates(t *testing.T) {
	const body = "MOVQ $0,SI\nloop:\nMOVQ AX,16(SP)(SI*8)\nADDQ $1,SI\nCMPQ SI,$3\nJB loop\nMOVQ 32(SP),AX"
	fn, sig, source := fixedLocalCountedLoopFixture(t, body)
	requireX86GoAssemblerResult(t, "amd64", source, true)
	for _, mutation := range []string{"none", "early offset", "missing iteration", "inline offset", "snapshot copy"} {
		t.Run(mutation, func(t *testing.T) {
			proved, err := proveX86FixedLocal(fn, sig)
			if err != nil {
				t.Fatal(err)
			}
			lower := &amd64Ctx{fixedLocal: proved.x86FixedLocal}
			found := false
			for _, instruction := range proved.Instrs {
				for operand, access := range instruction.x86FixedLocalMemory {
					if len(access.iterationOffsets) == 0 {
						continue
					}
					found = true
					if len(access.iterationOffsets) != 3 || access.offset != access.iterationOffsets[0] {
						t.Fatal("loop did not preserve its complete ordered access inventory", access)
					}
					for iteration, offsets := range access.iterationOffsets {
						for _, offset := range offsets {
							if offset != int64(16+8*iteration) {
								t.Fatal("one original SP residue or iteration changed bytes", offsets)
							}
						}
					}
					switch mutation {
					case "early offset":
						// Mutate the original instruction's backing slice directly.
						// Its separately frozen expected access must not change.
						access.iterationOffsets[0][0]++
					case "missing iteration":
						access.iterationOffsets = access.iterationOffsets[1:]
					case "inline offset":
						access.offset[0]++
					case "snapshot copy":
						copy := cloneX86ReplayFixedLocalMemory(instruction.x86FixedLocalMemory)
						copy[operand].iterationOffsets[0][0]++
						if !lower.fixedLocalMemoryCertified(instruction, operand) {
							t.Fatal("changing a copied snapshot changed its source")
						}
						access = copy[operand]
					}
					instruction.x86FixedLocalMemory[operand] = access
					if lower.fixedLocalMemoryCertified(instruction, operand) != (mutation == "none") {
						t.Fatal("incomplete or changed iteration series retained its authority")
					}
				}
			}
			if !found {
				t.Fatal("no loop access received a complete series")
			}
		})
	}
}

func TestGoAMD64FixedLocalCountedLoopBudgetIsAtomic(t *testing.T) {
	const body = "MOVQ $0,SI\nloop:\nMOVQ AX,16(SP)(SI*8)\nADDQ $1,SI\nCMPQ SI,$3\nJB loop\nMOVQ 32(SP),AX"
	fn, sig, _ := fixedLocalCountedLoopFixture(t, body)
	for _, budget := range []x86FixedLocalBudget{{steps: 9, bytes: 64 << 20}, {steps: 1 << 18, bytes: 9 * fn.FrameSize}} {
		proof := &x86FixedLocalProof{frame: fn.FrameSize}
		if err := replayX86FixedLocal(&fn, sig, proof, 0, &budget, nil, nil); err == nil {
			t.Fatal("partial counted-loop execution exhausted its budget but succeeded")
		}
		for _, instruction := range fn.Instrs {
			if len(instruction.x86FixedLocalMemory) != 0 {
				t.Fatal("unfinished counted loop published provisional access history")
			}
		}
	}
}

func TestGoAMD64FixedLocalCountedLoopPreservesGenericCFG(t *testing.T) {
	var original strings.Builder
	for index, row := range []struct{ name, body string }{
		{"wrapping counter with fixed access", "MOVQ $-1,SI\nloop:\nMOVQ AX,16(SP)\nADDQ $1,SI\nCMPQ SI,$3\nJB loop\nMOVQ 16(SP),AX"},
		{"counter replaced with fixed access", "MOVQ $0,SI\nloop:\nMOVQ $3,SI\nMOVQ AX,16(SP)\nADDQ $1,SI\nCMPQ SI,$3\nJB loop\nMOVQ 16(SP),AX"},
		{"counter replaced before indexed access", "MOVQ $0,SI\nloop:\nMOVQ $3,SI\nMOVQ AX,16(SP)(SI*8)\nADDQ $1,SI\nCMPQ SI,$3\nJB loop\nMOVQ 40(SP),AX"},
	} {
		fn, sig, source := fixedLocalCountedLoopFixture(t, row.body)
		original.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", index), 1))
		t.Run(row.name, func(t *testing.T) {
			plain := fn
			plain.Instrs = append([]Instr(nil), fn.Instrs...)
			edges, instructions, err := fixedLocalEdges(plain)
			if err != nil {
				t.Fatal(err)
			}
			proof := &x86FixedLocalProof{frame: fn.FrameSize}
			budget := x86FixedLocalBudget{steps: 1 << 18, bytes: 64 << 20}
			for residue := 0; residue < 8; residue++ {
				if err := replayX86FixedLocalCFG(&plain, sig, proof, residue, &budget, nil, edges, instructions, nil, nil, nil); err != nil {
					t.Fatal("the original generic CFG must independently establish this fixture", err)
				}
			}
			if _, err := proveX86FixedLocal(fn, sig); err != nil {
				t.Fatal("new loop closure must preserve ordinary CFG acceptance", err)
			}
		})
	}
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
}

func TestGoAMD64FixedLocalReplayLateResidueFailureIsAtomic(t *testing.T) {
	fn, sig, source := fixedLocalGPFixture(t, "MOVQ AX,16(SP)\nMOVQ AX,24(SP)\nMOVQ 24(SP),AX")
	requireX86GoAssemblerResult(t, "amd64", source, true)
	proof := &x86FixedLocalProof{frame: fn.FrameSize}
	budget := x86FixedLocalBudget{steps: 1 << 18, bytes: 64 << 20}
	if err := replayX86FixedLocal(&fn, sig, proof, 0, &budget, nil, nil); err != nil {
		t.Fatal(err)
	}
	last := -1
	for index, instruction := range fn.Instrs {
		if len(instruction.x86FixedLocalMemory) != 0 {
			last = index
		}
	}
	if last < 0 {
		t.Fatal("fixture has no late memory annotation")
	}
	for operand, access := range fn.Instrs[last].x86FixedLocalMemory {
		access.width++
		fn.Instrs[last].x86FixedLocalMemory[operand] = access
	}
	before := make([]map[int]x86FixedLocalAccess, len(fn.Instrs))
	for index, instruction := range fn.Instrs {
		before[index] = cloneX86ReplayFixedLocalMemory(instruction.x86FixedLocalMemory)
	}
	if err := replayX86FixedLocal(&fn, sig, proof, 1, &budget, nil, nil); err == nil {
		t.Fatal("late cross-residue shape mismatch was accepted")
	}
	for index, instruction := range fn.Instrs {
		if !reflect.DeepEqual(before[index], instruction.x86FixedLocalMemory) {
			t.Fatal("failed final validation published an earlier partial annotation", index)
		}
	}
}
