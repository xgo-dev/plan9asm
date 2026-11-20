package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86TrapOnlyLogicalFPShadowThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, move := range []struct {
			name  string
			width int
		}{{"MOVB", 1}, {"MOVW", 2}, {"MOVL", 4}, {"MOVQ", 8}} {
			if target.arch == "386" && move.width == 8 {
				continue // Go's GP qword row is mode64-only; X/m64 is separate.
			}
			for _, trap := range []string{"UNDEF", "UD2"} {
				for _, graph := range []string{"linear", "two-trap-branches"} {
					body := fmt.Sprintf("%s $17,x+0(FP)\n%s\nRET\n", move.name, trap)
					if graph == "two-trap-branches" {
						body = fmt.Sprintf("%s $17,x+0(FP)\nCMPL x+0(FP),$0\nJE second\n%s\nsecond:\n%s\nRET\n", move.name, trap, trap)
					}
					source := "TEXT ·value(SB),4,$0-16\n" + body
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(target.triple+"/"+move.name+"/"+trap+"/"+graph+"/"+api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, "func value(x uint64) uint64", target.arch, target.triple, api)
							if err != nil || ir == "" || !strings.Contains(ir, `asm sideeffect "ud2"`) || !strings.Contains(ir, "unreachable") {
								t.Fatal("complete trap-only logical shadow source did not retain its nonreturning fault", err)
							}
						})
					}
				}
			}
		}
	}
}

func TestX86TrapOnlyLogicalShadowCannotAuthorizeReturningOrUnknownSource(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range []struct{ name, declaration, body string }{
			{"ordinary-return", "func value(x uint64) uint64", "MOVB $17,x+0(FP)\nMOVL $0,ret+8(FP)\nMOVL $0,ret+12(FP)\nRET"},
			{"one-normal-path", "func value(x uint64) uint64", "MOVB $17,x+0(FP)\nCMPL x+0(FP),$0\nJE normal\nUD2\nnormal:\nMOVL $0,ret+8(FP)\nMOVL $0,ret+12(FP)\nRET"},
			{"unknown-input", "func value(x uint64) uint64", "MOVB AX,x+0(FP)\nUD2\nRET"},
			{"pointer", "func value(x *byte) uint64", "MOVB $17,x+0(FP)\nUD2\nRET"},
			{"bool-cross-field-byte-view", "func value(x bool,y byte) uint64", "MOVW $0x1102,x+0(FP)\nUD2\nRET"},
			{"padding", "func value(x byte,y uint64) uint64", "MOVW $17,x+0(FP)\nUD2\nRET"},
			{"native-store", "func value(x uint64) uint64", "MOVB $17,x+0(FP)\nMOVB $1,(AX)\nUD2\nRET"},
			{"unknown-dead-effect", "func value(x uint64) uint64", "MOVB $17,x+0(FP)\nUD2\nMOVB (AX),BX\nRET"},
			{"CALL", "func value(x uint64) uint64", "MOVB $17,x+0(FP)\nCALL unbound(SB)\nUD2\nRET"},
			{"external-tail", "func value(x uint64) uint64", "MOVB $17,x+0(FP)\nJMP unbound(SB)\nUD2\nRET"},
			{"cycle-only", "func value(x uint64) uint64", "MOVB $17,x+0(FP)\nagain:\nJMP again\nUD2\nRET"},
			{"one-cyclic-path", "func value(x uint64) uint64", "MOVB $17,x+0(FP)\nCMPL x+0(FP),$0\nJE again\nUD2\nagain:\nJMP again\nRET"},
			{"one-falloff-path", "func value(x uint64) uint64", "MOVB $17,x+0(FP)\nCMPL x+0(FP),$0\nJE outside\nUD2\noutside:\nNOP"},
			{"raw-trap", "func value(x uint64) uint64", "MOVB $17,x+0(FP)\nBYTE $0x0f\nBYTE $0x0b\nRET"},
			{"malformed-trap", "func value(x uint64) uint64", "MOVB $17,x+0(FP)\nUD2 AX\nRET"},
		} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+row.name+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, "TEXT ·value(SB),4,$0-32\n"+row.body+"\n", row.declaration, arch, testTargetTriple("linux", arch), api)
					if err == nil || ir != "" {
						t.Fatalf("trap syntax authorized a returning/unknown/source-native role: %v, IR bytes=%d", err, len(ir))
					}
				})
			}
		}
	}
}

func TestX86TrapOnlyFPShadowOriginalGoForms(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source strings.Builder
			count := 0
			for _, move := range []string{"MOVB", "MOVW", "MOVL", "MOVQ"} {
				if move == "MOVQ" && target.arch == "386" {
					continue
				}
				for _, trap := range []string{"UNDEF", "UD2"} {
					fmt.Fprintf(&source, "TEXT ·trap%d(SB),4,$0-16\n%s $17,x+0(FP)\n%s\nRET\n", count, move, trap)
					count++
					fmt.Fprintf(&source, "TEXT ·trap%d(SB),4,$0-16\n%s $17,x+0(FP)\nCMPL x+0(FP),$0\nJE second%d\n%s\nsecond%d:\n%s\nRET\n", count, move, count, trap, count, trap)
					count++
				}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			t.Logf("actual Go accepts all %d complete trap-only forms, including CMP operand order; object-only, not executed", count)
		})
	}
}

func TestX86TrapOnlyCFGRequiresEveryReachableSuccessor(t *testing.T) {
	for _, row := range []struct {
		name         string
		instructions []Instr
		edges        [][]int
		reachable    []int
		valid        bool
	}{
		{"linear", []Instr{{Op: "NOP"}, {Op: "UD2"}, {Op: OpRET}}, [][]int{{1}, nil, nil}, []int{0, 1}, true},
		{"two-traps", []Instr{{Op: "JE"}, {Op: "UD2"}, {Op: "UNDEF"}}, [][]int{{1, 2}, nil, nil}, []int{0, 1, 2}, true},
		{"one-cycle", []Instr{{Op: "JE"}, {Op: OpJMP}, {Op: "UD2"}}, [][]int{{1, 2}, {1}, nil}, []int{0, 1, 2}, false},
		{"one-return", []Instr{{Op: "JE"}, {Op: OpRET}, {Op: "UD2"}}, [][]int{{1, 2}, nil, nil}, []int{0, 1, 2}, false},
		{"nontrap-leaf", []Instr{{Op: "NOP"}}, [][]int{nil}, []int{0}, false},
		{"invalid-trap", []Instr{{Op: "UD2", Args: []Operand{{Kind: OpReg, Reg: AX}}}}, [][]int{nil}, []int{0}, false},
	} {
		for _, arch := range []string{"386", "amd64"} {
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				states := make(map[int]x86ResultState)
				for _, pc := range row.reachable {
					states[pc] = x86ResultState{}
				}
				if got := x86ResultAllPathsTerminateInTrap(row.instructions, row.edges, states, arch); got != row.valid {
					t.Fatalf("all-successor termination differs: got %t want %t", got, row.valid)
				}
			})
		}
	}
}
