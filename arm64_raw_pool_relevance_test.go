package plan9asm

import "testing"

func TestARM64PoolIgnoresUnrelatedMaskDefinition(t *testing.T) {
	flow := arm64PoolTestFlow(t, []string{"mov x1, #8", "and x2, x0, #24", "ret"})
	if got := flow.affineInterval(2, arm64PoolRegisterExpression(1)); got != (arm64PoolInterval{8, 8}) {
		t.Fatalf("unrelated mask lost a constant: %+v", got)
	}
	if _, queried := flow.affineCache[arm64PoolAffineQuery{1, arm64PoolRegisterExpression(0)}]; queried {
		t.Fatal("an unrelated mask definition started another affine proof")
	}
}
