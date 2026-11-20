package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// AMD64's private lowering currently uses one virtual cell per PUSH. Go's
// actual W/Q operations move SP by two/eight bytes. A partial native pop must
// not consume an entire private cell or invent zero bytes for a later wide pop.
func TestX86ValueStackMixedNativeWidthsNeedByteAccurateStorage(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		if target.arch != "amd64" {
			continue
		}
		for _, row := range []struct {
			name, body string
		}{
			{"wide-first", "PUSHQ value+0(FP)\nPOPW AX\nPUSHW $9\nPOPQ BX\nMOVQ BX,ret+8(FP)"},
			{"narrow-first", "PUSHW $7\nPOPQ AX\nPUSHQ $9\nPOPW BX\nMOVQ $1,ret+8(FP)"},
		} {
			t.Run(target.triple+"/"+row.name, func(t *testing.T) {
				source := "TEXT ·Value(SB),4,$0-16\n" + row.body + "\nRET\n"
				// Both sources balance their actual total SP delta. The first
				// recombines bytes; the second can overwrite the entry word.
				// Keep actual Go objects, but never execute the unsafe source.
				for _, result := range []bool{false, true} {
					text, declaration := source, "func Value(value uint64) uint64"
					if !result {
						text = strings.ReplaceAll(text, "$0-16", "$0-8")
						text = strings.ReplaceAll(text, "MOVQ BX,ret+8(FP)\n", "")
						text = strings.ReplaceAll(text, "MOVQ $1,ret+8(FP)\n", "")
						declaration = "func Value(value uint64)"
					}
					x86LEAActualTargetGoObject(t, "amd64", target.triple, text)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, text, declaration, "amd64", target.triple, api)
						if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Errorf("%s result=%v changed native byte-stack semantics into virtual-cell semantics: %v", api, result, err)
						}
					}
				}
			})
		}
		// Different widths may nest when each cell is consumed whole. This
		// retains the original value without granting a physical SP alias.
		t.Run(target.triple+"/nested-complete-cells", func(t *testing.T) {
			const source = "TEXT ·Value(SB),4,$0-16\nPUSHQ value+0(FP)\nPUSHW $9\nPOPW AX\nPOPQ BX\nMOVQ BX,ret+8(FP)\nRET\n"
			x86LEAActualTargetGoObject(t, "amd64", target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source,
					"func Value(value uint64) uint64", "amd64", target.triple, api)
				if err != nil || ir == "" {
					t.Fatal("complete nested cells lost their independent numerical input", api, err)
				}
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, text, level)
					}
				}
			}
		})
	}
}

func TestX86ValueStackCellWidthsKeepCloneAndJoinIdentity(t *testing.T) {
	for _, widths := range []struct{ left, right string }{
		{"Q", "Q"}, {"W", "W"}, {"Q", "W"}, {"W", "Q"},
	} {
		for _, flags := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s-%s/flags=%v", widths.left, widths.right, flags), func(t *testing.T) {
				makeState := func(width string) x86ResultState {
					state := x86ResultState{valueStack: &x86ResultValueStack{id: true},
						flags: x86ByteFlagsAll, direction: x86ResultDirectionForward}
					text := "PUSH" + width + " $7"
					if flags {
						text = "PUSHF" + width
					}
					ins := x86ScalarLaneInstruction(t, text)
					if !x86ResultTransfer(ins, &state, nil, 0, "amd64") {
						t.Fatal("independent complete immediate push rejected")
					}
					return state
				}
				left, right := makeState(widths.left), makeState(widths.right)
				clone := left.clone()
				pop := x86ScalarLaneInstruction(t, "POP"+widths.left+" AX")
				if !x86ResultTransfer(pop, &clone, nil, 0, "amd64") || len(left.valueStack.bytes) != 8 {
					t.Fatal("a cloned pop changed the original private cell")
				}
				replacement := "Q"
				if widths.left == "Q" {
					replacement = "W"
				}
				push := x86ScalarLaneInstruction(t, "PUSH"+replacement+" $9")
				if !x86ResultTransfer(push, &clone, nil, 0, "amd64") {
					t.Fatal("a consumed cell could not be independently reused")
				}
				original := left.clone()
				if !x86ResultTransfer(pop, &original, nil, 0, "amd64") {
					t.Fatal("a cloned cell replacement changed the original source width")
				}
				merged := left.intersect(right)
				got := x86ResultTransfer(pop, &merged, nil, 0, "amd64")
				if got != (widths.left == widths.right) {
					t.Fatal("equal virtual depth erased a native cell-width distinction", widths, got)
				}
			})
		}
	}
}
