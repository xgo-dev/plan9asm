package plan9asm

import (
	"fmt"
	"testing"
)

func TestARM64PoolAffineBitGuardForms(t *testing.T) {
	for _, op := range []string{"tbz", "tbnz"} {
		for bit := uint(0); bit < 64; bit++ {
			register := "x1"
			if bit < 32 {
				register = "w1"
			}
			for _, displacement := range []int{-8, 8} {
				name := fmt.Sprintf("%s %s, #%d, #%d", op, register, bit, displacement)
				t.Run(name, func(t *testing.T) {
					word := assembleARM64LLVMWords(t, []string{name}, "")[0]
					flow := &arm64RawPoolValues{words: []uint32{0, 0, word, 0, 0}}
					for _, taken := range []bool{false, true} {
						target := 3
						if taken {
							target = 2 + displacement/4
						}
						constraint, ok := flow.affineEdgeConstraint(arm64RawPoolEdge{2, target})
						mask := uint64(1) << bit
						value := uint64(0)
						if taken == (op == "tbnz") {
							value = mask
						}
						if !ok || constraint.expression != arm64PoolRegisterExpression(1) ||
							constraint.mask != mask || constraint.interval != (arm64PoolInterval{value, value}) {
							t.Fatalf("taken=%v: constraint=%+v valid=%v", taken, constraint, ok)
						}
					}
				})
			}
		}
	}
}
