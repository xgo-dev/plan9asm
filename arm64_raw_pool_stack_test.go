package plan9asm

import "testing"

func TestARM64PoolSavedStackValues(t *testing.T) {
	for _, test := range []struct {
		name, save, load string
		want             uint64
	}{
		{"scaled", "str x2, [sp, #8]", "ldr x3, [sp, #8]", 64},
		{"unscaled", "stur x2, [sp, #9]", "ldur x3, [sp, #9]", 64},
		{"pair-first", "stp x2, x1, [sp, #8]", "ldp x3, x4, [sp, #8]", 64},
		{"pair-second", "stp x1, x2, [sp, #8]", "ldp x4, x3, [sp, #8]", 64},
		{"scalar-from-pair", "stp x1, x2, [sp]", "ldr x3, [sp, #8]", 64},
		{"nontemporal", "stnp x2, x1, [sp, #8]", "ldnp x3, x4, [sp, #8]", 64},
		{"zero-source", "str xzr, [sp, #8]", "ldr x3, [sp, #8]", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			flow := arm64PoolTestFlow(t, []string{
				"sub sp, sp, #32", "mov x2, #64", test.save, "mov x2, #99",
				"strb w0, [sp, #31]", test.load, "nop", "add sp, sp, #32", "ret",
			})
			want := arm64PoolInterval{test.want, test.want}
			if got := flow.affineInterval(6, arm64PoolRegisterExpression(3)); got != want {
				t.Fatalf("saved value = %+v, want %+v", got, want)
			}
		})
	}
}

func TestARM64PoolSavedStackRelationship(t *testing.T) {
	flow := arm64PoolTestFlow(t, []string{
		"sub sp, sp, #32", "add x2, x1, #8", "str x2, [sp, #8]", "mov x2, #99",
		"ldr x3, [sp, #8]", "nop", "add sp, sp, #32", "ret",
	})
	expression := arm64PoolRegisterExpression(3)
	expression.add(arm64PoolRegisterExpression(1), -1)
	if got := flow.affineInterval(5, expression); got != (arm64PoolInterval{8, 8}) {
		t.Fatalf("saved relationship = %+v", got)
	}
}

func TestARM64PoolStackReadsRejectAmbiguousMemory(t *testing.T) {
	for _, test := range []struct {
		name, save, middle, load string
	}{
		{"overlapping-byte", "str x2, [sp, #8]", "strb w0, [sp, #9]", "ldr x3, [sp, #8]"},
		{"overlapping-pair", "str x2, [sp, #8]", "stp d0, d1, [sp]", "ldr x3, [sp, #8]"},
		{"possible-alias", "str x2, [sp, #8]", "str x0, [x5]", "ldr x3, [sp, #8]"},
		{"stack-moved", "str x2, [sp, #8]", "add sp, sp, #16", "ldr x3, [sp, #8]"},
		{"stack-writeback", "str x2, [sp, #8]", "ldr x5, [sp], #16", "ldr x3, [sp, #8]"},
		{"narrow-save", "str w2, [sp, #8]", "nop", "ldr x3, [sp, #8]"},
		{"narrow-load", "str x2, [sp, #8]", "nop", "ldr w3, [sp, #8]"},
		{"different-slot", "str x2, [sp, #16]", "nop", "ldr x3, [sp, #8]"},
		{"unknown-call", "str x2, [sp, #8]", "blr x5", "ldr x3, [sp, #8]"},
	} {
		t.Run(test.name, func(t *testing.T) {
			flow := arm64PoolTestFlow(t, []string{
				"sub sp, sp, #32", "mov x2, #64", test.save, test.middle,
				test.load, "nop", "ret",
			})
			if got := flow.affineInterval(5, arm64PoolRegisterExpression(3)); got != arm64PoolUnknownInterval {
				t.Fatalf("ambiguous saved value accepted: %+v", got)
			}
		})
	}
	flow := arm64PoolTestFlow(t, []string{
		"sub sp, sp, #32", "mov x2, #64", "str x2, [sp, #8]", "add x1, x1, #1",
		"ldr x3, [sp, #8]", "nop", "ret",
	})
	expression := arm64PoolRegisterExpression(3)
	expression.add(arm64PoolRegisterExpression(1), 1)
	if got := flow.affineInterval(5, expression); got != arm64PoolUnknownInterval {
		t.Fatalf("changed residual was rewound to its old value: %+v", got)
	}
}

func TestARM64PoolOpaqueLoopPreservesUnmodifiedValues(t *testing.T) {
	for _, change := range []bool{false, true} {
		body := "nop"
		if change {
			body = "add x3, x3, #1"
		}
		flow := arm64PoolTestFlow(t, []string{
			"mov x3, #64", "mov x1, #2", body, "sub x1, x1, #1", "cbnz x1, #-8",
			"cbz x0, #12", "mov x1, #2", "b #-20", "ret",
		})
		entry := flow.counterLoopEntry(2, 4)
		want := arm64PoolInterval{64, 64}
		if change {
			want = arm64PoolUnknownInterval
		}
		if got := entry.invariantIntervalProof(2, arm64PoolRegisterExpression(3), true); got != want {
			t.Fatalf("changing=%v: enclosing-loop entry=%+v, want %+v", change, got, want)
		}
	}
}
