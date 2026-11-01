package plan9asm

import "testing"

func TestARM64PoolRevisitInconclusiveQuery(t *testing.T) {
	for _, invariant := range []bool{false, true} {
		flow := arm64PoolTestFlow(t, []string{"mov x1, #8", "ret"})
		query := arm64PoolAffineQuery{1, arm64PoolRegisterExpression(1)}
		// An earlier nested proof may exhaust the shared work budget. Unknown
		// records that failed attempt, not a fact about the register's value.
		flow.affineCache = map[arm64PoolAffineQuery]arm64PoolInterval{query: arm64PoolUnknownInterval}
		flow.invariantCache = map[arm64PoolAffineQuery]arm64PoolInterval{query: arm64PoolUnknownInterval}
		flow.affineActive = make(map[arm64PoolAffineQuery]bool)
		var got arm64PoolInterval
		if invariant {
			got = flow.invariantInterval(query.at, query.expression)
		} else {
			got = flow.affineInterval(query.at, query.expression)
		}
		if got != (arm64PoolInterval{8, 8}) {
			t.Fatalf("invariant=%v: a previous inconclusive attempt poisoned the new proof: %+v", invariant, got)
		}
	}
}
