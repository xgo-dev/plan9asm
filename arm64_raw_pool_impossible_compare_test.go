package plan9asm

import "testing"

func TestARM64PoolImpossibleConstantCompareEdges(t *testing.T) {
	for _, test := range []struct {
		compare, branch string
		limit           string
	}{
		{"cmp x1,x2", "b.hs #12", "32"},
		{"cmp x1,x2", "b.hi #12", "31"},
		{"cmp x1,x2", "b.lo #12", "16"},
		{"cmp x1,x2", "b.ls #12", "15"},
		{"cmp x1,#32", "b.hs #12", "0"},
		{"cmn x1,x2", "b.hs #12", "15"},
	} {
		flow := arm64PoolTestFlow(t, []string{
			"and x1,x0,#3", "add x1,x1,#16", "mov x2,#" + test.limit,
			test.compare, test.branch, "mov x3,#7", "b #8", "mov x3,#99", "ret",
		})
		if !flow.excluded[arm64RawPoolEdge{4, 7}] {
			t.Fatalf("%s/%s did not exclude its impossible edge", test.compare, test.branch)
		}
		if got := flow.affineInterval(8, arm64PoolRegisterExpression(3)); got != (arm64PoolInterval{7, 7}) {
			t.Fatalf("impossible path polluted the joined value: %+v", got)
		}
	}
}

func TestARM64PoolCompareEdgesRemainWhenUnproved(t *testing.T) {
	for _, setup := range [][]string{
		{"nop", "mov x2,#32", "cmp x1,x2", "nop"},
		{"mov x1,#16", "nop", "cmp x1,x2", "nop"},
		{"mov x1,#16", "mov x2,#32", "cmp x1,x2", "cmp x0,#0"},
		{"mov x1,#16", "mov x2,#32", "cmp x1,x2", "mov x1,#99"},
		{"mov x1,#16", "cbz x0,#12", "cmp x1,#32", "nop"},
	} {
		lines := append(append([]string(nil), setup...), "b.hs #12", "mov x3,#7", "b #8", "mov x3,#99", "ret")
		flow := arm64PoolTestFlow(t, lines)
		if flow.excluded[arm64RawPoolEdge{4, 7}] {
			t.Fatalf("unproved/bypassed/overwritten comparison excluded an edge: %v", setup)
		}
	}
}
