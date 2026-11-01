package plan9asm

// Prove the first comparison is equal on every external entry. This excludes
// only the nonzero backedge; it does not infer a general multi-iteration range.
// Rewind the compared expression, not independent ranges for its operands.
func (flow *arm64RawPoolValues) proveRelationalOneIterationLoop(latch int) {
	word := flow.words[latch]
	if word&0xff00001f != 0x54000001 {
		return
	}
	head := latch + int(int32(word<<8)>>13)
	if flow.excluded[arm64RawPoolEdge{latch, head}] || !flow.straightLineLoopBody(head, latch) {
		return
	}
	compare, _, after, known := flow.affineFlagSourceBefore(latch)
	if !known || after <= head || after > latch {
		return
	}
	_, expression, affine := flow.affineDefinition(compare &^ ((1 << 29) | 31))
	if !affine {
		return
	}
	for at := after - 2; at >= head; at-- {
		writes, _ := flow.gpWrites(flow.words[at])
		if affected := writes & expression.registerMask(); affected != 0 {
			destination, value, valid := flow.affineDefinition(flow.words[at])
			if !valid || affected != 1<<uint(destination) || !expression.substitute(destination, value) {
				return
			}
		}
	}
	entry := flow.counterLoopEntry(head, latch)
	if entry == nil {
		return
	}
	entry = entry.numericValues()
	// Rewinding can introduce an invariant step (for example RDVL). Prove
	// its entry value independently; a prior enclosing iteration remains
	// opaque whenever it could have changed the queried register.
	for register, coefficient := range expression.coefficient {
		if coefficient == 0 {
			continue
		}
		bound := entry.invariantInterval(head, arm64PoolRegisterExpression(register))
		if bound.low == bound.high {
			if !expression.substitute(register, arm64PoolAffine{constant: bound.low}) {
				return
			}
		}
	}
	if entry.affineInterval(head, expression) == (arm64PoolInterval{0, 0}) {
		flow.excludeEdge(arm64RawPoolEdge{latch, head})
	}
}
