package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type fixedLocalIntegerCompareCase struct {
	name, operation, destination string
	width                        int
	legacy, self                 bool
}

func fixedLocalIntegerCompareCases() []fixedLocalIntegerCompareCase {
	var rows []fixedLocalIntegerCompareCase
	for index, name := range x86PackedIntegerCompareTestNames {
		legacy := index < 8
		banks := []string{"X", "Y"}
		if legacy {
			banks = banks[:1]
		}
		for _, bank := range banks {
			width := 16
			if bank == "Y" {
				width = 32
			}
			add := func(label, operands, destination string, self bool) {
				rows = append(rows, fixedLocalIntegerCompareCase{
					name + "/" + bank + "/" + label, name + " " + operands,
					destination, width, legacy, self,
				})
			}
			if legacy {
				add("register", "X1,X0", "X0", false)
				add("alias", "X0,X0", "X0", true)
				add("private", "64(BP),X0", "X0", false)
				add("native", "(SI),X0", "X0", false)
				add("unknown self", "X15,X15", "X15", true)
				continue
			}
			for _, destination := range []string{bank + "2", bank + "0", bank + "1"} {
				add("register "+destination, bank+"0,"+bank+"1,"+destination, destination, false)
			}
			for _, memory := range []string{"64(BP)", "65(BP)", "(SI)"} {
				add("memory "+memory, memory+","+bank+"1,"+bank+"2", bank+"2", false)
			}
			for _, destination := range []string{bank + "6", bank + "15"} {
				add("unknown self "+destination, bank+"15,"+bank+"15,"+destination, destination, true)
			}
		}
	}
	return rows
}

func fixedLocalIntegerCompareSource(row fixedLocalIntegerCompareCase) string {
	// Keep the complete original aligned scratch function. Store the compared
	// low qword into its actual result slot, so the comparison is observable.
	low := strings.Replace(row.destination, "Y", "X", 1)
	return fixedLocalVEXAssembly(row.operation + "\nMOVQ " + low + ",AX\nMOVQ AX,128(BP)")
}

func TestGoAMD64FixedLocalIntegerCompareCompleteSources(t *testing.T) {
	rows := fixedLocalIntegerCompareCases()
	if len(rows) != 168 {
		t.Fatal("fixed-frame source inventory changed", len(rows))
	}
	var original strings.Builder
	for index, row := range rows {
		source := fixedLocalIntegerCompareSource(row)
		original.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", index), 1))
		t.Run(row.name, func(t *testing.T) {
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(p *uint64, a uint64) uint64", "RET")
			if _, err := proveX86FixedLocal(file.Funcs[0], sig); err != nil {
				t.Fatal("complete integer-comparison source rejected", err)
			}
		})
	}
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
}

func TestGoAMD64FixedLocalIntegerCompareAliasesAndFlags(t *testing.T) {
	for index, name := range x86PackedIntegerCompareTestNames {
		legacy := index < 8
		for _, width := range []int{16, 32} {
			if legacy && width != 16 {
				continue
			}
			bank := "X"
			if width == 32 {
				bank = "Y"
			}
			for _, self := range []bool{false, true} {
				for _, upper := range []uint64{0, 1 << 50, 0xffffffffffff0000} {
					t.Run(fmt.Sprintf("%s/%s/self=%v/upper=%x", name, bank, self, upper), func(t *testing.T) {
						operands := bank + "1," + bank + "0"
						if self {
							operands = bank + "0," + bank + "0"
						}
						if !legacy {
							operands += "," + bank + "0"
						}
						ins := x86ScalarLaneInstruction(t, name+" "+operands)
						state := x86FixedLocalState{vectors: map[Reg]uint64{"Z0": upper, "Z1": 0}, flags: x86ByteFlagsAll}
						mask := x86CallerVectorByteMask(int64(width))
						if !self {
							state.vectors["Z0"] |= mask
							state.vectors["Z1"] = mask
						}
						if err := fixedLocalVectorStep(&ins, &state, nil, 0); err != nil {
							t.Fatal("shared compare effect was not consumed", err)
						}
						want := ^uint64(0)
						if legacy {
							want = upper | mask
						}
						if state.vectors["Z0"] != want || state.flags != x86ByteFlagsAll {
							t.Fatal("comparison changed upper aliases or architectural FLAGS", state)
						}
					})
				}
			}
		}
	}
}

func TestGoAMD64FixedLocalIntegerCompareConsumerBoundaries(t *testing.T) {
	for index, name := range x86PackedIntegerCompareTestNames {
		legacy := index < 8
		banks := []string{"X", "Y"}
		if legacy {
			banks = banks[:1]
		}
		for _, bank := range banks {
			operands := "64(BP)," + bank + "1"
			if !legacy {
				operands += "," + bank + "2"
			}
			_, sig, source := fixedLocalVEXFixture(t, name+" "+operands)
			changes := []struct{ name, from, to string }{
				{"missing byte", "MOVQ AX,64(BP)", "MOVB AX,64(BP)"},
				{"private pointer", "MOVQ AX,64(BP)", "MOVQ SP,64(BP)"},
				{"missing second input", "VMOVDQU 64(BP),Y1", "NOP"},
				{"outside frame", name + " 64(BP)", name + " 512(BP)"},
			}
			if legacy {
				changes = append(changes, struct{ name, from, to string }{"unaligned legacy", name + " 64(BP)", name + " 65(BP)"})
			}
			for _, change := range changes {
				t.Run(name+"/"+bank+"/"+change.name, func(t *testing.T) {
					changed := strings.Replace(source, change.from, change.to, 1)
					if changed == source {
						t.Fatal("complete-source mutation did not change its intended input")
					}
					file, err := Parse(ArchAMD64, changed)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := proveX86FixedLocal(file.Funcs[0], sig); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("compare supplied missing private storage or input authority", err)
					}
				})
			}
		}
	}
	// These valid ISA forms have separate MMX or EVEX mask-result consumers.
	// Descriptor metadata must not silently grant fixed-frame vector storage.
	var separate []string
	for index, name := range x86PackedIntegerCompareTestNames {
		if index < 8 {
			if index%4 != 3 {
				separate = append(separate, name+" M0,M1")
			}
			continue
		}
		for _, bank := range []string{"X", "Y", "Z"} {
			separate = append(separate, name+" "+bank+"0,"+bank+"1,K0", name+" "+bank+"0,"+bank+"1,K1,K2")
		}
	}
	for _, name := range x86ImmediateCompareResultMembers {
		for _, bank := range []string{"X", "Y", "Z"} {
			separate = append(separate, name+" $255,"+bank+"0,"+bank+"1,K0", name+" $7,"+bank+"0,"+bank+"1,K1,K2")
		}
	}
	for _, operation := range separate {
		t.Run(operation, func(t *testing.T) {
			ins := x86ScalarLaneInstruction(t, operation)
			effect, known, err := x86TypedPackedIntegerCompareByteEffect(ins.Op, ins, "amd64")
			if !known || err != nil || effect.vector != (x86TypedVectorEffect{}) {
				t.Fatal("separate valid ISA form changed grammar or gained vector storage", err, effect)
			}
			if _, known, err := fixedLocalVectorByteEffect(ins); known && err == nil {
				t.Fatal("MMX or EVEX mask result acquired this fixed-frame vector consumer")
			}
		})
	}
}
