package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86GoCallerPackedNarrowDestinationAliasesKeepOriginalInputs(t *testing.T) {
	// Whole-source initialization isolates concatenation and alias ordering
	// from the finer per-input-byte dependency test. Expected half masks are
	// independent constants, repeated once for each 128-bit chunk.
	for _, name := range []string{"VPACKSSDW", "VPACKSSWB", "VPACKUSDW", "VPACKUSWB"} {
		for bankIndex, bank := range []string{"X", "Y", "Z"} {
			for _, mask := range []string{"", "merge", "zero"} {
				for destination := 0; destination < 3; destination++ {
					opcode, operands := name, bank+"0,"+bank+"1"
					if mask != "" {
						operands += ",K1"
					}
					if mask == "zero" {
						opcode += ".Z"
					}
					operands += fmt.Sprintf(",%s%d", bank, destination)
					row := opcode + " " + operands
					t.Run(row, func(t *testing.T) {
						goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", true)
						file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
						if err != nil {
							t.Fatal(err)
						}
						width := x86CallerVectorByteMask(int64(16 << bankIndex))
						for _, sample := range []struct{ first, second, halves uint64 }{
							{0, ^uint64(0), 0x00ff00ff00ff00ff},
							{^uint64(0), 0, 0xff00ff00ff00ff00},
							{^uint64(0), ^uint64(0), ^uint64(0)},
							{0, 0, 0},
						} {
							ins := file.Funcs[0].Instrs[1]
							state := &x86SourceStackState{
								vectors: map[Reg]uint64{"Z0": sample.first, "Z1": sample.second, "Z2": 0xaaaaaaaaaaaaaaaa},
								masks:   map[Reg]bool{"K1": true},
							}
							root := Reg(fmt.Sprintf("Z%d", destination))
							old := state.vectors[root]
							want := sample.halves & width
							if mask == "merge" {
								want &= old
							}
							want |= ^width
							if !x86CallerVectorMoveStep(&ins, state, nil) || state.vectors[root] != want {
								t.Fatalf("source/destination alias grant %s first=%x second=%x got=%x want=%x",
									row, sample.first, sample.second, state.vectors[root], want)
							}
						}
					})
				}
			}
		}
	}
}

func TestX86GoCallerPackedNarrowLegacyUpperBytesDoNotBecomeInitialized(t *testing.T) {
	for _, name := range []string{"PACKSSLW", "PACKSSWB", "PACKUSDW", "PACKUSWB"} {
		row := name + " X0,X1"
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		state := &x86SourceStackState{vectors: map[Reg]uint64{"Z0": ^uint64(0), "Z1": 0xffff}}
		ins := file.Funcs[0].Instrs[1]
		if !x86CallerVectorMoveStep(&ins, state, nil) || state.vectors["Z1"] != 0xffff {
			t.Fatal("legacy PACK borrowed VEX upper-zero initialization", row, state.vectors["Z1"])
		}
		// A following YMM use cannot inherit initialized upper bytes from
		// the instruction's legal XMM-only grammar.
		next := Instr{Op: "VPACKSSDW", Args: []Operand{
			{Kind: OpReg, Reg: "Y1"}, {Kind: OpReg, Reg: "Y1"}, {Kind: OpReg, Reg: "Y2"},
		}}
		if !x86CallerVectorMoveStep(&next, state, nil) || state.vectors["Z2"]&0xffff0000 != 0 {
			t.Fatal(strings.Join([]string{"legacy PACK initialized an unrelated YMM upper chunk", row}, ": "))
		}
	}
}
