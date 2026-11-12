package plan9asm

// Remove only edges whose independently bounded incoming value cannot satisfy
// the unchanged CMP/CMN condition. This is proof-graph refinement, not deletion
// of executable branches. In particular, a larger VL can make an entire SVE
// path unreachable even though its unconstrained pool offsets do not fit.
func (flow *arm64RawPoolValues) refineConstantCompareEdges() {
	for at, word := range flow.words {
		if word&0xff000010 != 0x54000000 {
			continue
		}
		switch word & 15 {
		case 2, 3, 8, 9:
		default:
			continue
		}
		target := at + int(int32(word<<8)>>13)
		for _, next := range []int{at + 1, target} {
			if next < 0 || next >= len(flow.before) {
				continue
			}
			edge := arm64RawPoolEdge{at, next}
			guard, ok := flow.affineEdgeConstraint(edge)
			if !ok || guard.after != 0 || guard.mask != 0 {
				continue
			}
			numeric := flow.numericValues()
			input := numeric.affineInterval(at, guard.expression)
			if input.high < guard.interval.low || input.low > guard.interval.high {
				flow.excludeEdge(edge)
			}
		}
	}
}
