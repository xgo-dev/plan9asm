package plan9asm

import (
	"fmt"
	"math"
	"testing"
)

func TestARM64PoolConstantRegisterCompareGuards(t *testing.T) {
	for _, operand := range []struct {
		text  string
		input uint64
		limit uint64
	}{
		{"x2", 15, 15},
		{"x2,lsl #1", 15, 30},
		{"x2,lsr #1", 30, 15},
		{"x2,asr #1", math.MaxUint64 - 29, math.MaxUint64 - 14},
		{"w2,uxtb #1", 0xff0f, 30},
		{"w2,uxth #1", 0xff0f, 0x1fe1e},
		{"w2,uxtw #1", 15, 30},
		{"x2,uxtx #1", 15, 30},
		{"w2,sxtb #1", 0xff, math.MaxUint64 - 1},
		{"w2,sxth #1", 0xffff, math.MaxUint64 - 1},
		{"w2,sxtw #1", math.MaxUint64, math.MaxUint64 - 1},
		{"x2,sxtx #1", math.MaxUint64, math.MaxUint64 - 1},
	} {
		for _, condition := range []string{"hs", "lo", "hi", "ls"} {
			t.Run(operand.text+"/"+condition, func(t *testing.T) {
				flow := arm64PoolTestFlow(t, []string{
					fmt.Sprintf("mov x2,#%#x", operand.input), "cmp x1," + operand.text,
					"b." + condition + " #8", "nop", "ret",
				})
				constraint, ok := flow.affineEdgeConstraint(arm64RawPoolEdge{2, 4})
				want := arm64PoolUnknownInterval
				switch condition {
				case "hs":
					want.low = operand.limit
				case "lo":
					want.high = operand.limit - 1
				case "hi":
					want.low = operand.limit + 1
				case "ls":
					want.high = operand.limit
				}
				if !ok || constraint.expression != arm64PoolRegisterExpression(1) || constraint.interval != want {
					t.Fatalf("guard=%+v/%v, want R1 in %+v", constraint, ok, want)
				}
			})
		}
	}
}

func TestARM64PoolConstantCompareRejectsUnprovedLimits(t *testing.T) {
	for _, lines := range [][]string{
		{"nop", "cmp x1,x2", "b.hs #8", "nop", "ret"},
		{"mov x2,#15", "cmp w1,w2", "b.hs #8", "nop", "ret"},
		{"mov x2,#15", "cmp sp,x2", "b.hs #8", "nop", "ret"},
		{"adr x2,#16", "cmp x1,x2", "b.hs #8", "nop", "ret"},
	} {
		flow := arm64PoolTestFlow(t, lines)
		flow.poolOrigins = map[int]uint64{0: 16}
		if constraint, ok := flow.affineEdgeConstraint(arm64RawPoolEdge{2, 4}); ok {
			t.Fatalf("%v invented numeric limit: %+v", lines, constraint)
		}
	}
	flow := arm64PoolTestFlow(t, []string{"mov x2,#15", "cmp x1,x2", "mov x2,#7", "b.hs #8", "nop", "ret"})
	if constraint, ok := flow.affineEdgeConstraint(arm64RawPoolEdge{3, 5}); !ok || constraint.interval.low != 15 {
		t.Fatalf("comparison used its overwritten limit: %+v/%v", constraint, ok)
	}
}

func TestARM64PoolConstantRegisterCMNGuards(t *testing.T) {
	for _, condition := range []string{"hs", "lo", "hi", "ls"} {
		flow := arm64PoolTestFlow(t, []string{"mov x2,#15", "cmn x1,x2,lsl #1", "b." + condition + " #8", "nop", "ret"})
		constraint, ok := flow.affineEdgeConstraint(arm64RawPoolEdge{2, 4})
		threshold := uint64(math.MaxUint64 - 29)
		want := arm64PoolUnknownInterval
		switch condition {
		case "hs":
			want.low = threshold
		case "lo":
			want.high = threshold - 1
		case "hi":
			want.low = threshold + 1
		case "ls":
			want.high = threshold
		}
		if !ok || constraint.expression != arm64PoolRegisterExpression(1) || constraint.interval != want {
			t.Fatalf("CMN %s: %+v/%v, want %+v", condition, constraint, ok, want)
		}
	}
	for _, test := range []struct{ setup, compare, branch string }{
		{"mov x2,#-1", "cmp x1,x2", "b.hi #8"},
		{"mov x2,#0", "cmp x1,x2", "b.lo #8"},
		{"mov x2,#1", "cmn x1,x2", "b.hi #8"},
	} {
		flow := arm64PoolTestFlow(t, []string{test.setup, test.compare, test.branch, "nop", "ret"})
		if guard, ok := flow.affineEdgeConstraint(arm64RawPoolEdge{2, 4}); ok && guard.interval != arm64PoolUnknownInterval {
			t.Fatalf("impossible comparison wrapped to a live bound: %+v", guard)
		}
	}
}
