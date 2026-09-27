package plan9asm

import "testing"

func TestARM64PoolCarriedAddressCounterRelation(t *testing.T) {
	for _, test := range []struct {
		name          string
		initial, load string
		want          arm64PoolInterval
	}{
		{"decreasing", "mov x3, #64", "ldr x4, [x3], #-8", arm64PoolInterval{8, 64}},
		{"increasing", "mov x3, #0", "ldr x4, [x3], #8", arm64PoolInterval{0, 56}},
	} {
		t.Run(test.name, func(t *testing.T) {
			flow := arm64PoolTestFlow(t, []string{
				test.initial, "mov x1, #0", "mov x2, #8", test.load,
				"add x1, x1, #1", "cmp x1, x2", "b.lt #-12", "ret",
			})
			if got := flow.affineInterval(3, arm64PoolRegisterExpression(3)); got != test.want {
				t.Fatalf("carried address = %+v, want %+v", got, test.want)
			}
		})
	}
	flow := arm64PoolTestFlow(t, []string{
		"mov x3, #64", "mov x1, #0", "mov x2, #8", "ldr x4, [x3], #-8",
		"add x3, x3, x5", "add x1, x1, #1", "cmp x1, x2", "b.lt #-16", "ret",
	})
	if got := flow.affineInterval(3, arm64PoolRegisterExpression(3)); got != arm64PoolUnknownInterval {
		t.Fatalf("nonconstant address recurrence accepted: %+v", got)
	}
}
