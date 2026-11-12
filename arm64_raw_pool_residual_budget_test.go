package plan9asm

import (
	"math"
	"testing"
)

func TestARM64PoolAffineResidualBudget(t *testing.T) {
	word := assembleARM64LLVMWords(t, []string{"mov x15, #8"}, "")[0]
	newFlow := func() *arm64RawPoolValues {
		return &arm64RawPoolValues{words: []uint32{word, 0}, before: [][]int{{-1}, {0}}}
	}
	query := arm64PoolRegisterExpression(14)
	difference := query
	if !difference.add(arm64PoolRegisterExpression(15), -1) {
		t.Fatal("cannot construct difference")
	}
	wide := arm64PoolConstraint{expression: difference, interval: arm64PoolInterval{1, math.MaxUint64}}
	flow := newFlow()
	bound, ok := flow.affineConstraintBound(1, query, wide)
	if ok || len(flow.affineCache) != 0 || flow.affineWork != 0 {
		t.Fatalf("uninformative NE decomposition spent proof budget: bound=%+v ok=%v queries=%d work=%d",
			bound, ok, len(flow.affineCache), flow.affineWork)
	}
	// The direct nonzero fact is still useful. Only speculative decomposition
	// into other registers is deferred until another guard bounds its width.
	if bound, ok := flow.affineConstraintBound(1, difference, wide); !ok || bound != wide.interval {
		t.Fatalf("lost direct nonzero guard: %+v %v", bound, ok)
	}
	tight := wide
	tight.interval.high = 19
	flow = newFlow()
	if bound, ok := flow.affineConstraintBound(1, query, tight); !ok || bound != (arm64PoolInterval{9, 27}) {
		t.Fatalf("bounded residual: %+v %v", bound, ok)
	}
	// A partially eliminated guard is not an independent subproblem. Unless
	// its residual is already invariant, wait for reaching definitions to
	// normalize it instead of recursively chasing the same unknown operands.
	flow = newFlow()
	flow.words[0] = assembleARM64LLVMWords(t, []string{"mov x15, x0"}, "")[0]
	bound, ok = flow.affineConstraintBound(1, query, tight)
	if ok || len(flow.affineCache) != 0 {
		t.Fatalf("partially eliminated guard recursed: bound=%+v ok=%v queries=%d", bound, ok, len(flow.affineCache))
	}
}
