package plan9asm

import (
	"fmt"
	"testing"
)

func TestARM64PoolOrderedCounterLoops(t *testing.T) {
	for _, condition := range []struct {
		up, down  string
		inclusive bool
	}{
		{"lt", "gt", false}, {"lo", "hi", false},
		{"le", "ge", true}, {"ls", "hs", true},
	} {
		for _, ascending := range []bool{true, false} {
			name := fmt.Sprintf("%s/up=%v", condition.up, ascending)
			t.Run(name, func(t *testing.T) {
				initial, update, branch := "mov x1, #8", "add x1, x1, #1", condition.up
				expression := arm64PoolRegisterExpression(2)
				expression.add(arm64PoolRegisterExpression(1), -1)
				if !ascending {
					initial, update, branch = "mov x1, #24", "sub x1, x1, #1", condition.down
					expression = arm64PoolRegisterExpression(1)
					expression.add(arm64PoolRegisterExpression(2), -1)
				}
				lines := []string{initial, "mov x2, #16", "nop", update,
					"cmp x1, x2", "orr w3, w3, w4", "b." + branch + " #-16", "ret"}
				flow := arm64PoolTestFlow(t, lines)
				low := uint64(1)
				if condition.inclusive {
					low = 0
				}
				want := arm64PoolInterval{low, 8}
				if got := flow.affineInterval(2, expression); got != want {
					t.Fatalf("remaining = %+v, want %+v", got, want)
				}
				// Swap CMP operands and use the inverse ordered condition.
				lines[4] = "cmp x2, x1"
				branch = condition.down
				if !ascending {
					branch = condition.up
				}
				lines[6] = "b." + branch + " #-16"
				flow = arm64PoolTestFlow(t, lines)
				if got := flow.affineInterval(2, expression); got != want {
					t.Fatalf("reversed comparison remaining = %+v, want %+v", got, want)
				}
			})
		}
	}
}

func TestARM64PoolOrderedLoopRejectsUnprovedInduction(t *testing.T) {
	base := []string{"mov x1, #8", "mov x2, #16", "nop",
		"add x1, x1, #1", "cmp x1, x2", "nop", "b.lt #-16", "ret"}
	for _, test := range []struct {
		name string
		at   int
		line string
	}{
		{"negative-counter", 0, "mov x1, #-8"},
		{"zero-remaining", 0, "mov x1, #16"},
		{"unknown-limit", 1, "mov x2, x5"},
		{"changing-limit", 2, "add x2, x2, #1"},
		{"wrong-step", 3, "add x1, x1, #2"},
		{"wrong-direction", 3, "sub x1, x1, #1"},
		{"truncating-update", 3, "add w1, w1, #1"},
		{"word-compare", 4, "cmp w1, w2"},
		{"flag-clobber", 5, "tst x3, x4"},
		{"operand-clobber", 5, "mov x1, x3"},
		{"side-entry", 1, "cbz x5, #8"},
	} {
		t.Run(test.name, func(t *testing.T) {
			lines := append([]string(nil), base...)
			lines[test.at] = test.line
			flow := arm64PoolTestFlow(t, lines)
			if bound, ok := flow.loopBounds[2]; ok {
				t.Fatalf("unproved induction accepted: %+v", bound)
			}
		})
	}
}
