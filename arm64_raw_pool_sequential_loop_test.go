package plan9asm

import "testing"

func TestARM64PoolCounterAfterProvedEarlierLoop(t *testing.T) {
	flow := arm64PoolTestFlow(t, []string{
		"and x17,x0,#15", "add x17,x17,#8", "and x6,x17,#24", "neg x7,x6",
		"nop", "add x7,x7,#8", "cbnz x7,#-8", "cmp x17,x6", "b.eq #20",
		"sub x16,x17,x6", "nop", "subs x16,x16,#1", "b.ne #-8", "ret",
	})
	if got := flow.affineInterval(10, arm64PoolRegisterExpression(16)); got != (arm64PoolInterval{1, 7}) {
		t.Fatalf("tail counter after unchanged earlier-loop values=%+v, want [1,7]", got)
	}
}

func TestARM64PoolSequentialLoopRejectsChangedRelations(t *testing.T) {
	for _, change := range []string{"add x14,x14,#1", "add x17,x17,#1", "ldr x14,[x2]", "ldr x17,[x2]"} {
		t.Run(change, func(t *testing.T) {
			flow := arm64PoolTestFlow(t, []string{
				"and x14,x0,#15", "add x14,x14,#8", "mov x16,#0", "sub x17,x14,x16",
				"and x6,x17,#24", "neg x7,x6", change, "add x7,x7,#8", "cbnz x7,#-8",
				"cmp x17,x6", "b.eq #28", "sub x17,x14,x6", "add x6,x6,x16",
				"sub x16,x17,x16", "nop", "subs x16,x16,#1", "b.ne #-8", "ret",
			})
			if got := flow.affineInterval(14, arm64PoolRegisterExpression(16)); got.low >= 1 && got.high <= 7 {
				t.Fatalf("changed length/guard incorrectly retained the old remainder: %+v", got)
			}
		})
	}
}

func TestARM64PoolInvariantLoopForgetsChangingConstraints(t *testing.T) {
	flow := arm64PoolTestFlow(t, []string{
		"and x7,x0,#8", "add x7,x7,#8", "nop", "sub x7,x7,#8", "cbnz x7,#-8", "ret",
	})
	stable := arm64PoolConstraint{expression: arm64PoolRegisterExpression(17), interval: arm64PoolInterval{1, 7}}
	changing := arm64PoolConstraint{expression: arm64PoolRegisterExpression(7), interval: arm64PoolInterval{8, 8}}
	historical := stable
	historical.after = 1
	state := arm64PoolAffineState{
		at: 2, expression: arm64PoolRegisterExpression(17),
		constraints: [8]arm64PoolConstraint{changing, historical, stable}, count: 3,
	}
	if latch, ok := flow.rewindInvariantLoop(&state); !ok || latch != 4 {
		t.Fatalf("unchanged query not rewound: latch=%d ok=%v", latch, ok)
	}
	if state.count != 1 || state.constraints != ([8]arm64PoolConstraint{stable}) {
		t.Fatalf("retained a changing or inactive constraint: %+v", state)
	}
	state.expression = arm64PoolRegisterExpression(7)
	if _, ok := flow.rewindInvariantLoop(&state); ok {
		t.Fatal("rewound a changing counter as invariant")
	}
	flow.loopLatches = nil
	state.expression = arm64PoolRegisterExpression(17)
	if _, ok := flow.rewindInvariantLoop(&state); ok {
		t.Fatal("rewound an uncertified loop")
	}
}

func TestARM64PoolCounterAfterEarlierLoopPreservesRelationalGuard(t *testing.T) {
	flow := arm64PoolTestFlow(t, []string{
		"and x14,x0,#15", "add x14,x14,#8", "mov x16,#0", "sub x17,x14,x16",
		"and x6,x17,#24", "neg x7,x6", "nop", "add x7,x7,#8", "cbnz x7,#-8",
		"cmp x17,x6", "b.eq #28", "sub x17,x14,x6", "add x6,x6,x16",
		"sub x16,x17,x16", "nop", "subs x16,x16,#1", "b.ne #-8", "ret",
	})
	if got := flow.affineInterval(14, arm64PoolRegisterExpression(16)); got != (arm64PoolInterval{1, 7}) {
		t.Fatalf("tail counter with an earlier equivalent guard=%+v, want [1,7]", got)
	}
}
