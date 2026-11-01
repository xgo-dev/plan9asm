package plan9asm

import "testing"

func TestARM64PoolMaskedDifference(t *testing.T) {
	for _, test := range []struct {
		setup, mask string
	}{
		{"mov x2,#24", "and x3,x1,#24"},
		{"mov x2,#24", "ands x3,x1,#24"},
		{"mov x2,#24", "and x3,x1,x2"},
		{"mov x2,#24", "ands x3,x2,x1"},
		{"mov x2,#-25", "bic x3,x1,x2"},
		{"mov x2,#-25", "bics x3,x1,x2"},
		{"mov x2,#12", "and x3,x1,x2,lsl #1"},
		{"mov x2,#48", "and x3,x1,x2,lsr #1"},
		{"mov x2,#48", "and x3,x1,x2,asr #1"},
		{"mov x2,#12", "and x3,x1,x2,ror #63"},
	} {
		t.Run(test.mask, func(t *testing.T) {
			flow := arm64PoolTestFlow(t, []string{
				"and x4,x0,#15", "add x4,x4,#8", "mov x1,x4", test.setup, test.mask, "ret",
			})
			for _, source := range []int{1, 4} {
				query := arm64PoolRegisterExpression(source)
				query.add(arm64PoolRegisterExpression(3), -1)
				if got := flow.affineInterval(5, query); got != (arm64PoolInterval{0, 7}) {
					t.Errorf("source=x%d, masked difference=%+v, want [0,7]", source, got)
				}
			}
		})
	}
}

func TestARM64PoolMaskedDifferenceRejectsUnrelatedValues(t *testing.T) {
	for _, mask := range []string{"and x3,x1,x2", "and w3,w1,#24"} {
		flow := arm64PoolTestFlow(t, []string{mask, "ret"})
		query := arm64PoolRegisterExpression(4)
		query.add(arm64PoolRegisterExpression(3), -1)
		if got := flow.affineInterval(1, query); got != arm64PoolUnknownInterval {
			t.Fatalf("%s: unrelated difference bounded as %+v", mask, got)
		}
	}
}

func TestARM64PoolMaskedDifferenceIntersectsNonzeroGuard(t *testing.T) {
	flow := arm64PoolTestFlow(t, []string{
		"and x1,x0,#15", "add x1,x1,#8", "and x3,x1,#24",
		"cmp x1,x3", "b.eq #12", "sub x4,x1,x3", "nop", "ret",
	})
	if got := flow.affineInterval(6, arm64PoolRegisterExpression(4)); got != (arm64PoolInterval{1, 7}) {
		t.Fatalf("nonzero masked difference=%+v, want [1,7]", got)
	}
	query := arm64PoolRegisterExpression(4)
	query.constant = ^uint64(0)
	if got := flow.affineInterval(6, query); got != (arm64PoolInterval{0, 6}) {
		t.Fatalf("nonzero masked difference minus one=%+v, want [0,6]", got)
	}
}
