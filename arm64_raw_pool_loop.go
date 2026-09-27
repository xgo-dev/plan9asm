package plan9asm

import "golang.org/x/arch/arm64/arm64asm"

func (flow *arm64RawPoolValues) clearValueCaches() {
	flow.cache = make(map[arm64RawPoolValue]uint64)
	flow.active = make(map[arm64RawPoolValue]bool)
	flow.affineCache = nil
	flow.affineActive = nil
	flow.affineWork = 0
	flow.invariantCache = nil
	flow.maskConstants = make(map[int]uint64)
}

// Positive bounds remain valid across queries on this immutable graph.
// Unknown can instead reflect a recursive dependency or an exhausted shared
// budget. Keep that negative cache within one proof, not across fresh roots.
func (flow *arm64RawPoolValues) beginAffineProof() {
	if len(flow.affineActive) != 0 {
		return
	}
	flow.affineWork = 0
	for query, bound := range flow.affineCache {
		if bound == arm64PoolUnknownInterval {
			delete(flow.affineCache, query)
		}
	}
	for query, bound := range flow.invariantCache {
		if bound == arm64PoolUnknownInterval {
			delete(flow.invariantCache, query)
		}
	}
}

func (flow *arm64RawPoolValues) excludeEdge(edge arm64RawPoolEdge) {
	if flow.excluded == nil {
		flow.excluded = make(map[arm64RawPoolEdge]bool)
	}
	flow.excluded[edge] = true
	var remaining []int
	for _, previous := range flow.before[edge.to] {
		if previous != edge.from {
			remaining = append(remaining, previous)
		}
	}
	flow.before[edge.to] = remaining
	flow.pruneUnreachablePredecessors()
	flow.clearValueCaches()
}

func (flow *arm64RawPoolValues) pruneUnreachablePredecessors() {
	successors := make([][]int, len(flow.before))
	var queue []int
	for at, predecessors := range flow.before {
		for _, previous := range predecessors {
			if previous < 0 {
				queue = append(queue, at)
			} else {
				successors[previous] = append(successors[previous], at)
			}
		}
	}
	reachable := make([]bool, len(flow.before))
	for len(queue) > 0 {
		at := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if !reachable[at] {
			reachable[at] = true
			queue = append(queue, successors[at]...)
		}
	}
	for at, predecessors := range flow.before {
		var remaining []int
		for _, previous := range predecessors {
			if previous < 0 || reachable[previous] {
				remaining = append(remaining, previous)
			}
		}
		flow.before[at] = remaining
	}
}

// Refine a proof graph only with facts established on its unreduced input.
// This never rewrites executable control flow. The pointer-use walker shares
// the excluded-edge witnesses, rather than silently ignoring an arbitrary path.
func (flow *arm64RawPoolValues) prepareControlFlow() {
	// A proven one-iteration loop can sharpen a later branch, which in turn
	// sharpens another loop's entry. Refinements only remove proven-impossible
	// paths or add independently proved invariants. A cap loses precision only.
	for pass := 0; pass < 3; pass++ {
		excluded, loops := len(flow.excluded), len(flow.loopBounds)
		flow.refineBitEdges()
		for latch := range flow.words {
			flow.proveCounterLoop(latch)
			flow.proveOrderedCounterLoop(latch)
		}
		flow.clearValueCaches()
		if excluded == len(flow.excluded) && loops == len(flow.loopBounds) {
			break
		}
	}
}

func (flow *arm64RawPoolValues) refineBitEdges() {
	for at, word := range flow.words {
		if word&0x7e000000 != 0x36000000 {
			continue
		}
		input := flow.affineInterval(at, arm64PoolRegisterExpression(int(word&31)))
		target := at + int(int32(word<<13)>>18)
		for _, next := range []int{at + 1, target} {
			if next < 0 || next >= len(flow.before) {
				continue
			}
			edge := arm64RawPoolEdge{at, next}
			constraint, ok := flow.affineEdgeConstraint(edge)
			if !ok {
				continue
			}
			masked := arm64PoolMaskInterval(input, constraint.mask)
			if masked.high < constraint.interval.low || masked.low > constraint.interval.high {
				flow.excludeEdge(edge)
			}
		}
	}
}

// Recognize a single-entry straight-line body with exactly one counter update
// and a 64-bit nonzero backedge. Unknown effects, side entries, conditional body
// exits and flag clobbers are not induction proofs.
func (flow *arm64RawPoolValues) proveCounterLoop(latch int) {
	word := flow.words[latch]
	register := -1
	switch {
	case word&0xff000000 == 0xb5000000:
		register = int(word & 31)
	case word&0xff00001f == 0x54000001:
		compare, clobbered, ok := flow.affineFlagsBefore(latch)
		if !ok || compare&31 == 31 || clobbered&(1<<(compare&31)) != 0 {
			return
		}
		register = int(compare & 31)
	default:
		return
	}
	head := latch + int(int32(word<<8)>>13)
	update, delta, valid := flow.counterLoopUpdate(head, latch, register)
	if !valid {
		return
	}
	if word&0xff00001f == 0x54000001 {
		compare, _, _ := flow.affineFlagsBefore(latch)
		if compare != flow.words[update] {
			return
		}
	}

	entry := flow.counterLoopEntry(head, latch)
	if entry == nil {
		return
	}
	expression := arm64PoolRegisterExpression(register)
	initial := entry.affineInterval(head, expression)
	if upper := entry.upper(head, arm64asm.X0+arm64asm.Reg(register)); upper < initial.high {
		initial.high = upper
	}
	if initial.low > initial.high {
		return
	}
	if initial.low == initial.high && initial.low+delta == 0 {
		flow.excludeEdge(arm64RawPoolEdge{latch, head})
		return
	}
	// A unit countdown from a positive unsigned value cannot wrap before
	// reaching zero. At the loop head it stays in [1, initial.high]. Larger
	// steps require a divisibility proof and are deliberately not inferred.
	if delta != ^uint64(0) || initial.low == 0 || initial == arm64PoolUnknownInterval {
		return
	}
	if flow.loopBounds == nil {
		flow.loopBounds = make(map[int]arm64PoolConstraint)
	}
	flow.loopBounds[head] = arm64PoolConstraint{expression: expression, interval: arm64PoolInterval{1, initial.high}}
	flow.recordLoopLatch(head, latch)
	flow.clearValueCaches()
}

func (flow *arm64RawPoolValues) recordLoopLatch(head, latch int) {
	if flow.loopLatches == nil {
		flow.loopLatches = make(map[int]int)
	}
	flow.loopLatches[head] = latch
}

func (flow *arm64RawPoolValues) counterLoopUpdate(head, latch, register int) (int, uint64, bool) {
	if register >= 31 || head < 0 || head >= latch || latch-head > 512 {
		return 0, 0, false
	}
	for at := head + 1; at <= latch; at++ {
		if len(flow.before[at]) != 1 || flow.before[at][0] != at-1 {
			return 0, 0, false
		}
	}
	update := -1
	var delta uint64
	for at := head; at < latch; at++ {
		current := flow.words[at]
		// The body must fall through only, including instructions that would
		// otherwise appear harmless in the GP destination-effect classifier.
		if current&0x7c000000 == 0x14000000 || current&0x7e000000 == 0x34000000 ||
			current&0x7e000000 == 0x36000000 || current&0xff000010 == 0x54000000 ||
			current&0xfe000000 == 0xd6000000 {
			return 0, 0, false
		}
		writes, known := arm64RawPoolGPWrites(current)
		if !known {
			return 0, 0, false
		}
		if writes&(1<<uint(register)) == 0 {
			continue
		}
		destination, expression, affine := flow.affineDefinition(current)
		expected := arm64PoolRegisterExpression(register)
		if !affine || destination != register || expression.coefficient != expected.coefficient || update != -1 {
			return 0, 0, false
		}
		update, delta = at, expression.constant
	}
	if update == -1 || delta == 0 {
		return 0, 0, false
	}
	return update, delta, true
}

func (flow *arm64RawPoolValues) counterLoopEntry(head, latch int) *arm64RawPoolValues {
	// Infer the first iteration from external entry paths only. A prior body
	// execution reached through an enclosing loop is opaque: deleting a
	// backedge must not assume that such an earlier execution ran just once.
	entry := &arm64RawPoolValues{
		vectorBytes: flow.vectorBytes,
		words:       flow.words, before: append([][]int(nil), flow.before...),
		opaque: map[int]bool{latch: true}, loopBounds: flow.loopBounds,
		opaqueLoops: map[int]int{latch: head},
	}
	entry.clearValueCaches()
	entry.before[head] = nil
	for _, previous := range flow.before[head] {
		if previous == latch {
			continue
		}
		if previous >= head && previous < latch {
			return nil
		}
		entry.before[head] = append(entry.before[head], previous)
	}
	if len(entry.before[head]) == 0 {
		return nil
	}
	return entry
}

// An earlier execution of the same body is opaque for changing values, but
// cannot change an expression made solely from preserved registers. Checking
// every instruction avoids inventing a first-iteration value in an outer loop.
func (flow *arm64RawPoolValues) opaquePreserves(at int, expression arm64PoolAffine) bool {
	head, ok := flow.opaqueLoops[at]
	if !ok {
		return false
	}
	for instruction := head; instruction < at; instruction++ {
		if flow.affineWork >= 16384 {
			return false
		}
		flow.affineWork++
		writes, known := arm64RawPoolGPWrites(flow.words[instruction])
		if !known || writes&expression.registerMask() != 0 {
			return false
		}
	}
	return true
}
