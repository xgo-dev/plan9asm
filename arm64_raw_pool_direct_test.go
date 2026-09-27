package plan9asm

import (
	"fmt"
	"testing"
)

func TestARM64PoolDirectBoundsBeforeResidualProofs(t *testing.T) {
	flow := arm64PoolTestFlow(t, []string{
		"cmp x1, #7", "b.hi #28", "cmp x1, #1", "b.lo #20",
		"sub x2, x1, x3", "cmp x2, #5", "b.hi #8", "nop", "ret",
	})
	flow.clearValueCaches()
	if got := flow.affineInterval(7, arm64PoolRegisterExpression(1)); got != (arm64PoolInterval{1, 7}) {
		t.Fatalf("direct dominating bounds lost: %+v", got)
	}
	if len(flow.invariantCache) != 0 {
		t.Fatal("simple dominating guards speculatively queried unrelated residuals")
	}
}

func TestARM64PoolLongGuardSchedules(t *testing.T) {
	for _, constant := range []bool{false, true} {
		lines := []string{"mov x1, #8"}
		for n := 0; n < 12; n++ {
			if constant {
				lines = append(lines, "mov x2, #0", "cbnz x2, #0")
			} else {
				lines = append(lines, "cmp x2, #20", "b.hi #0")
			}
		}
		query := len(lines)
		lines = append(lines, "nop", "ret")
		for at := 2; at < query; at += 2 {
			if constant {
				lines[at] = fmt.Sprintf("cbnz x2, #%d", (query+1-at)*4)
			} else {
				lines[at] = fmt.Sprintf("b.hi #%d", (query+1-at)*4)
			}
		}
		flow := arm64PoolTestFlow(t, lines)
		if got := flow.affineInterval(query, arm64PoolRegisterExpression(1)); got != (arm64PoolInterval{8, 8}) {
			t.Fatalf("constant=%v: redundant guards exhausted the constraint budget: %+v", constant, got)
		}
	}
}

func TestARM64PoolMaskPredicateAfterLogicalFold(t *testing.T) {
	flow := arm64PoolTestFlow(t, []string{
		"mov x1, #0", "cmp x2, #16", "b.lo #36", "cmp x2, #19", "b.hi #28",
		"and x4, x2, #0xfffffffffffffff0", "cmp x2, x4", "b.eq #16",
		"orr x5, x1, x4", "sub x6, x2, x5", "nop", "ret",
	})
	if got := flow.affineInterval(10, arm64PoolRegisterExpression(6)); got != (arm64PoolInterval{1, 3}) {
		t.Fatalf("folded mask lost its nonempty-tail predicate: %+v", got)
	}
}
