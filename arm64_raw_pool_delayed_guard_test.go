package plan9asm

import "testing"

func TestARM64PoolHistoricalCompareOperands(t *testing.T) {
	for _, test := range []struct {
		name  string
		lines []string
		query int
		want  arm64PoolInterval
	}{
		{"masked-index-minus-one", []string{
			"and x2, x0, #7", "add x2, x2, #8", "and x4, x2, #0xfffffffffffffff8",
			"sub x6, x2, x4", "cmp x2, x4", "mov x4, xzr", "b.eq #12",
			"sub x6, x6, #1", "nop", "ret",
		}, 8, arm64PoolInterval{0, 6}},
		{"masked-tail", []string{
			"cmp x2, #8", "b.lo #40", "cmp x2, #15", "b.hi #32",
			"and x4, x2, #0xfffffffffffffff8", "sub x6, x2, x4",
			"cmp x2, x4", "mov x4, x0", "b.eq #12", "nop", "ret", "ret",
		}, 9, arm64PoolInterval{1, 7}},
		{"saved-cmp-operand", []string{
			"mov x6, x2", "cmp x2, #7", "mov x2, x0", "b.hi #8", "nop", "ret",
		}, 4, arm64PoolInterval{0, 7}},
		{"saved-adds-result", []string{
			"adds x2, x1, #1", "mov x6, x2", "mov x2, x0", "b.ne #8", "nop", "ret",
		}, 4, arm64PoolInterval{0, 0}},
		{"current-value-is-not-compared-value", []string{
			"cmp x6, #7", "mov x6, x0", "b.hi #8", "nop", "ret",
		}, 3, arm64PoolUnknownInterval},
		{"new-flags-win", []string{
			"mov x6, x2", "cmp x2, #7", "mov x2, x0", "tst x3, x4", "b.hi #8", "nop", "ret",
		}, 5, arm64PoolUnknownInterval},
		{"bypassed-compare", []string{
			"mov x6, x2", "cbz x1, #8", "cmp x2, #7", "mov x2, x0", "b.hi #8", "nop", "ret",
		}, 5, arm64PoolUnknownInterval},
	} {
		t.Run(test.name, func(t *testing.T) {
			flow := arm64PoolTestFlow(t, test.lines)
			if got := flow.affineInterval(test.query, arm64PoolRegisterExpression(6)); got != test.want {
				t.Fatalf("historical comparison range=%+v, want %+v", got, test.want)
			}
		})
	}
}
