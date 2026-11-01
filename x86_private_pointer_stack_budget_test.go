package plan9asm

import (
	"fmt"
	"testing"
)

func TestX86PrivatePointerStackMetadataHasOneCompleteWorkBudget(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			stack, word, limit, endpointBytes, widthBytes := "Q", 8, 504, 64, 8
			if arch == "386" {
				stack, word, limit, endpointBytes, widthBytes = "L", 4, 252, 32, 0
			}
			file, err := Parse(ArchAMD64, "TEXT Value(SB),4,$0-0\nPUSH"+stack+" BX\nPOP"+stack+" AX\nNOP\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			fn := file.Funcs[0]
			budget := new(x86ResultFlowBudget)
			fn.x86ResultFlowBudget = budget
			initial := x86ResultState{valueStack: new(x86ResultValueStack)}
			initial.pointerGP[3] = true
			transfer := func(_ int, ins Instr, state *x86ResultState, owned []bool, offset int64, arch string) bool {
				return x86ResultTransfer(ins, state, owned, offset, arch)
			}
			returned := false
			err = checkX86ResultSourceFlow(fn, initial, nil, 0, arch, transfer, func(state x86ResultState, _ int) error {
				returned = true
				if !state.pointerGP[0] || state.gp[0]&uint8((1<<uint(word))-1) != 0 {
					return fmt.Errorf("whole pointer cell lost its independent opaque role")
				}
				return nil
			})
			// Four source instructions and four actual must-defined visits.
			// This is independent logical domain accounting, not sizeof: the
			// endpoint bitmap spans 504/252 byte positions in 8/4 words, and
			// only AMD64 additionally has a W/Q virtual-cell identity bitmap.
			payload := x86IndependentResultBasePayload + limit + 14 + endpointBytes + widthBytes
			if err != nil || !returned || budget.visits != 4 || budget.bytes != 36*payload {
				t.Fatal("private endpoint/width metadata escaped the shared source/visit byte budget", budget, payload, err)
			}
		})
	}
}

func TestX86PrivatePointerStackMutationRevokesEveryOverlappingSpan(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			word := int(x86ResultPointerWord(arch))
			for changed := 0; changed < 3*word; changed++ {
				stack := &x86ResultValueStack{bytes: make([]uint8, 3*word)}
				stack.markPointerCell(word)
				stack.markPointerCell(3 * word)
				stack.revokePointerCells(changed, changed+1, word)
				if stack.pointerCell(word) != (changed >= word) || stack.pointerCell(3*word) != (changed < 2*word) {
					t.Fatal("byte write revoked the wrong complete pointer span", changed, stack.pointerCells)
				}
			}
			for _, end := range []int{1, 3*word + 1, 512} {
				stack := &x86ResultValueStack{bytes: make([]uint8, 3*word)}
				stack.markPointerCell(end)
				if stack.pointerCellsBounded(arch) {
					t.Fatal("an absent, partial or beyond-depth source word acquired an endpoint", end)
				}
			}
		})
	}
}
