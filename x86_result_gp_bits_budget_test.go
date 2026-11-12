package plan9asm

import (
	"strings"
	"testing"
)

func TestX86ResultGPBitsBudgetTracksFunctionDomains(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		word, stackBytes := "L", 252+14+32
		if arch == "amd64" {
			word, stackBytes = "Q", 504+14+64+8
		}
		stack := "PUSH" + word + " $1\nPOP" + word + " AX\n"
		mask := "VZEROALL\nPMOVMSKB X0,AX\n"
		for _, row := range []struct {
			name, body string
			additional int
		}{
			{"ordinary", "MOVL $1,AX\n", 0},
			{"movemask", mask, 11},
			{"stack", stack, stackBytes},
			{"both", mask + stack, stackBytes + 1},
			{"lowercase-movemask", mask, 11},
		} {
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				file, err := Parse(ArchAMD64, "TEXT Value(SB),4,$0-0\n"+row.body+"RET\n")
				if err != nil {
					t.Fatal(err)
				}
				fn := file.Funcs[0]
				if row.name == "lowercase-movemask" {
					fn.Instrs[2].Op = Op(strings.ToLower(string(fn.Instrs[2].Op)))
				}
				budget := new(x86ResultFlowBudget)
				fn.x86ResultFlowBudget = budget
				transfer := func(_ int, ins Instr, state *x86ResultState, owned []bool, offset int64, arch string) bool {
					return x86ResultTransfer(ins, state, owned, offset, arch)
				}
				returned := false
				err = checkX86ResultSourceFlow(fn, x86ResultState{}, nil, 0, arch, transfer, func(state x86ResultState, _ int) error {
					returned = state.gp[0]&15 == 15
					return nil
				})
				count := len(fn.Instrs) - 1
				want := 9 * count * (x86IndependentResultBasePayload + row.additional)
				if err != nil || !returned || budget.visits != count || budget.bytes != want {
					t.Fatal("function domains changed exact source/visit work", budget, want, err)
				}
			})
		}
	}
}
