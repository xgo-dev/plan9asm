package plan9asm

import "golang.org/x/arch/arm64/arm64asm"

// edgeUpper proves an unsigned bound on the selected CFG edge, not on the
// branch instruction as a whole. Inspect both successors even when they merge:
// the opposite edge must never inherit the taken edge's bound.
func (flow *arm64RawPoolValues) edgeUpper(edge arm64RawPoolEdge, reg arm64asm.Reg) (uint64, bool) {
	index, ok := arm64RawPoolGP(reg)
	if !ok || edge.from < 0 {
		return 0, false
	}
	word := flow.words[edge.from]
	conditional := word&0xff000010 == 0x54000000
	zeroBranch := word&0x7e000000 == 0x34000000
	if !conditional && !zeroBranch {
		return 0, false
	}
	target := edge.from + int(int32(word<<8)>>13)
	if target == edge.from+1 || edge.to != target && edge.to != edge.from+1 {
		return 0, false
	}
	taken := edge.to == target
	if zeroBranch {
		// W comparisons do not constrain an X register's upper 32 bits.
		if int(word&31) != index || word>>31 == 0 && reg >= arm64asm.X0 {
			return 0, false
		}
		return 0, taken == (word&(1<<24) == 0)
	}

	// Require the immediately preceding CMP to dominate this branch. Merely
	// looking at adjacent bytes is unsound when another edge bypasses the CMP.
	predecessors := flow.before[edge.from]
	if len(predecessors) != 1 || predecessors[0] != edge.from-1 || edge.from == 0 {
		return 0, false
	}
	compare := flow.words[edge.from-1]
	if compare&0x7f80001f != 0x7100001f || int(compare>>5&31) != index ||
		compare>>31 == 0 && reg >= arm64asm.X0 {
		return 0, false
	}
	immediate := uint64(compare >> 10 & 4095)
	if compare&(1<<22) != 0 {
		immediate <<= 12
	}
	condition := word & 15
	if !taken {
		condition ^= 1
	}
	switch condition {
	case 0, 9: // EQ or LS.
		return immediate, true
	case 3: // LO. For CMP #0 this edge has no feasible machine state.
		if immediate == 0 {
			return 0, true
		}
		return immediate - 1, true
	default:
		// Signed comparisons admit negative indexes; flags such as overflow
		// and sign alone do not establish an unsigned interval.
		return 0, false
	}
}
