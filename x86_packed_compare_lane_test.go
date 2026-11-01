package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type x86CompareLaneCase struct {
	op, bank string
	bytes    int
	width    int
	legacy   bool
}

// Independent of the implementation registry: ymm/yxm_q4 have eight X
// members; _yvpcmpeqb has two vector-result rows for each of eight V names.
// Its six EVEX K-result rows remain a different, complete-input domain.
func x86CompareLaneCases() []x86CompareLaneCase {
	var rows []x86CompareLaneCase
	for _, family := range []struct {
		legacy, vector string
		bytes          int
	}{
		{"PCMPEQB", "VPCMPEQB", 1}, {"PCMPEQW", "VPCMPEQW", 2},
		{"PCMPEQL", "VPCMPEQD", 4}, {"PCMPEQQ", "VPCMPEQQ", 8},
		{"PCMPGTB", "VPCMPGTB", 1}, {"PCMPGTW", "VPCMPGTW", 2},
		{"PCMPGTL", "VPCMPGTD", 4}, {"PCMPGTQ", "VPCMPGTQ", 8},
	} {
		rows = append(rows, x86CompareLaneCase{family.legacy, "X", family.bytes, 16, true})
		rows = append(rows, x86CompareLaneCase{family.vector, "X", family.bytes, 16, false})
		rows = append(rows, x86CompareLaneCase{family.vector, "Y", family.bytes, 32, false})
	}
	return rows
}

func (row x86CompareLaneCase) instruction(first string) string {
	if row.legacy {
		return row.op + " " + first + ",X2"
	}
	return row.op + " " + first + "," + row.bank + "1," + row.bank + "2"
}

func (row x86CompareLaneCase) second() int {
	if row.legacy {
		return 2
	}
	return 1
}

func TestX86PackedCompareLaneLoweringDefinedness(t *testing.T) {
	if len(x86CompareLaneCases()) != 24 {
		t.Fatal("incomplete independent legacy/VEX vector-result family")
	}
	for _, row := range x86CompareLaneCases() {
		for _, arch := range []string{"386", "amd64"} {
			t.Run(arch+"/"+row.op+"/"+row.bank, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.instruction(row.bank+"0"))
				full := uint64(1)<<uint(row.width) - 1
				for input := 0; input < 2; input++ {
					for missing := 0; missing < row.width; missing++ {
						state := x86RawMoveInitializedState()
						reg := 0
						if input == 1 {
							reg = row.second()
						}
						state.writeVector(reg, 64, ^(uint64(1) << uint(missing)), false)
						before, expected := state, state
						lane := (uint64(1)<<uint(row.bytes) - 1) << uint(missing/row.bytes*row.bytes)
						expected.writeVector(2, row.width, full&^lane, row.legacy)
						accepted, known := x86ResultVectorCompareStepWithRead(ins, &state, nil, arch, true)
						if !known || !accepted || !reflect.DeepEqual(state, expected) {
							t.Fatalf("input%d byte%d must invalidate exactly its complete comparison lane: accepted=%t known=%t", input, missing, accepted, known)
						}
						// A lowering-local numerical projection must not silently
						// relax the standalone complete-input observer.
						strict := before
						if accepted, _ := x86ResultVectorCompareStep(ins, &strict, nil, arch); accepted || !reflect.DeepEqual(strict, before) {
							t.Fatal("partial lowered bytes escaped into the standalone query")
						}
					}
				}
			})
		}
	}
}

func x86CompareLaneSource(row x86CompareLaneCase, memory bool) string {
	var source strings.Builder
	source.WriteString("TEXT ·query(SB),4,$0-12\nMOVQ input+0(FP),SI\n")
	partial := 0
	first := row.bank + "0"
	if memory {
		partial, first = row.second(), "(SI)"
	} else if row.legacy {
		source.WriteString("PXOR X2,X2\n")
	} else {
		fmt.Fprintf(&source, "VPXOR %s1,%s1,%s1\n", row.bank, row.bank, row.bank)
	}
	// Leave every other lane unknown; the final low-X lane works for both
	// X and Y comparisons without inventing initialized upper-Y contents.
	for offset := 0; offset < row.bytes; offset++ {
		fmt.Fprintf(&source, "PINSRB $%d,%d(SI),X%d\n", 16-row.bytes+offset, offset, partial)
	}
	source.WriteString(row.instruction(first) + "\n")
	fmt.Fprintf(&source, "PEXTRB $%d,X2,AX\nMOVL AX,ret+8(FP)\nRET\n", 16-row.bytes)
	return source.String()
}

func TestX86PackedCompareLaneCompleteSelectedUses(t *testing.T) {
	for _, row := range x86CompareLaneCases() {
		for _, memory := range []bool{false, true} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(fmt.Sprintf("%s/%s/memory=%t/%s", row.op, row.bank, memory, api), func(t *testing.T) {
					ir, err := x86PackedIntegerCompareAPI(t, x86CompareLaneSource(row, memory),
						"func query(input *[32]byte) uint32\n", "amd64", "x86_64-unknown-linux-gnu", api)
					if err != nil || ir == "" {
						t.Fatal("complete selected lane lost its actual input bytes", err)
					}
				})
			}
		}
	}
}

func TestX86PackedCompareLaneKeepsUnknownUses(t *testing.T) {
	for _, row := range x86CompareLaneCases() {
		for _, memory := range []bool{false, true} {
			source := x86CompareLaneSource(row, memory)
			partial := 0
			if memory {
				partial = row.second()
			}
			lastInsert := fmt.Sprintf("PINSRB $15,%d(SI),X%d\n", row.bytes-1, partial)
			for _, change := range []struct{ name, source string }{
				{"missing-lane-byte", strings.Replace(source, lastInsert, "", 1)},
				{"unknown-lane", strings.Replace(source, fmt.Sprintf("PEXTRB $%d,X2,AX", 16-row.bytes), "PEXTRB $0,X2,AX", 1)},
				{"full-vector-store", strings.Replace(source, "MOVL AX,ret+8(FP)", "MOVOU X2,(SI)\nMOVL AX,ret+8(FP)", 1)},
				{"missing-native-address", strings.Replace(source, "MOVQ input+0(FP),SI\n", "", 1)},
			} {
				if change.source == source {
					t.Fatal("negative mutation did not change its independent source", change.name)
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/%s/memory=%t/%s/%s", row.op, row.bank, memory, change.name, api), func(t *testing.T) {
						ir, err := x86PackedIntegerCompareAPI(t, change.source,
							"func query(input *[32]byte) uint32\n", "amd64", "x86_64-unknown-linux-gnu", api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("partial comparison invented missing data or native address facts", err)
						}
					})
				}
			}
		}
	}
}

func TestX86PackedCompareLaneRawAndKBoundaries(t *testing.T) {
	var original []x86RawIntegerCompareOriginCase
	for _, row := range x86CompareLaneCases() {
		original = append(original, x86RawIntegerCompareOriginCase{row: row.instruction(row.bank + "0"),
			bank: row.bank, destination: row.bank + "2", legacy: row.legacy})
	}
	codes := x86RawIntegerCompareOriginBytes(t, original)
	for index, row := range x86CompareLaneCases() {
		for _, arch := range []string{"386", "amd64"} {
			t.Run(arch+"/raw/"+row.op+"/"+row.bank, func(t *testing.T) {
				ins := x86RawMoveObservedInstruction(t, arch, codes[index])
				state := x86RawMoveInitializedState()
				state.xmm[0] &^= 1
				before := state
				if accepted, known := x86LoweredPackedIntegerCompareStep(ins, &state, nil, arch); !known || accepted || !reflect.DeepEqual(state, before) {
					t.Fatal("raw source projection borrowed the named partial-lane role")
				}
			})
		}
		if row.legacy || row.bank != "X" {
			continue
		}
		for _, bank := range []string{"X", "Y", "Z"} {
			for _, missingMask := range []bool{false, true} {
				t.Run(fmt.Sprintf("K/%s/%s/missingmask=%t", row.op, bank, missingMask), func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, row.op+" "+bank+"0,"+bank+"1,K1,K2")
					state := x86RawMoveInitializedState()
					if missingMask {
						state.masks[1] = false
					} else {
						state.xmm[0] &^= 1
					}
					before := state
					if accepted, known := x86ResultVectorCompareStepWithRead(ins, &state, nil, "amd64", true); !known || accepted || !reflect.DeepEqual(state, before) {
						t.Fatal("partial vector bytes or an unknown mask became a completely known K result")
					}
				})
			}
		}
	}
}

func TestX86PackedCompareLaneMemoryNeedsWholeTuple(t *testing.T) {
	for _, row := range x86CompareLaneCases() {
		for _, arch := range []string{"386", "amd64"} {
			t.Run(arch+"/"+row.op+"/"+row.bank, func(t *testing.T) {
				for _, available := range []int64{0, int64(row.bytes), int64(row.width - 1)} {
					ins := x86ScalarLaneInstruction(t, row.instruction("tuple<>(SB)"))
					state := x86RawMoveInitializedState()
					state.writeVector(row.second(), 64, uint64(1)<<uint(row.bytes)-1, false)
					state.loweredStaticReads = map[x86StaticSBAddress]int64{{symbol: "tuple<>"}: available}
					before := state
					if accepted, known := x86ResultVectorCompareStepWithRead(ins, &state, nil, arch, true); !known || accepted || !reflect.DeepEqual(state, before) {
						t.Fatal("a partial initialized result reduced the source's original full memory tuple", available)
					}
				}
				ins := x86ScalarLaneInstruction(t, row.instruction("(SI)"))
				state := x86RawMoveInitializedState()
				state.writeVector(row.second(), 64, uint64(1)<<uint(row.bytes)-1, false)
				state.pointerGP[6] = false // NUM bytes alone cannot establish an incoming address.
				before := state
				if accepted, known := x86ResultVectorCompareStepWithRead(ins, &state, nil, arch, true); !known || accepted || !reflect.DeepEqual(state, before) {
					t.Fatal("partial comparison borrowed an unproved native address")
				}
			})
		}
	}
}

func TestX86PackedCompareLaneProbeDoesNotProveResult(t *testing.T) {
	count := 0
	for _, row := range x86CompareLaneCases() {
		if row.legacy {
			continue
		}
		count++
		t.Run(row.op+"/"+row.bank, func(t *testing.T) {
			ins := x86ScalarLaneInstruction(t, row.instruction(row.bank+"0"))
			// The isolated void probe discards its result. Accepting that
			// IR does not initialize either operand or any low result lane.
			if err := ProbeInstruction(ArchAMD64, "amd64", ins); err != nil {
				t.Fatal("unused vector result cannot be retained in IR", err)
			}
			memory := x86ScalarLaneInstruction(t, row.instruction("(SI)"))
			if err := ProbeInstruction(ArchAMD64, "amd64", memory); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("discarding a result invented its memory address", err)
			}
			source := "TEXT ·query(SB),4,$0-4\n" + ins.Raw + "\n" +
				"PEXTRB $0,X2,AX\nMOVL AX,ret+0(FP)\nRET\n"
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86PackedIntegerCompareAPI(t, source, "func query() uint32\n",
					"amd64", "x86_64-unknown-linux-gnu", api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("IR-only probe lent initialized bytes to a real result", api, err)
				}
			}
		})
	}
	if count != 16 {
		t.Fatal("complete X/Y comparison probe family changed", count)
	}
}
