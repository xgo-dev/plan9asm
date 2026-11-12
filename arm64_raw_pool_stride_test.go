package plan9asm

import (
	"fmt"
	"testing"
)

func TestARM64PoolPowerOfTwoCounterStrides(t *testing.T) {
	for shift := uint(0); shift <= 23; shift++ {
		step := uint64(1) << shift
		for _, ascending := range []bool{false, true} {
			name := fmt.Sprintf("step=%d/ascending=%v", step, ascending)
			t.Run(name, func(t *testing.T) {
				lines := []string{fmt.Sprintf("and x1,x0,#%d", step), fmt.Sprintf("add x1,x1,#%d", step)}
				update := fmt.Sprintf("sub x1,x1,#%d", step)
				want := arm64PoolInterval{step, 2 * step}
				if ascending {
					lines = append(lines, "neg x1,x1")
					update = fmt.Sprintf("add x1,x1,#%d", step)
					want = arm64PoolInterval{-(2 * step), -step}
				}
				head := len(lines)
				lines = append(lines, "nop", update, "cbnz x1,#-8", "ret")
				flow := arm64PoolTestFlow(t, lines)
				if got := flow.affineInterval(head, arm64PoolRegisterExpression(1)); got != want {
					t.Fatalf("counter bound=%+v, want %+v", got, want)
				}
			})
		}
	}
}

func TestARM64PoolCounterStrideFlags(t *testing.T) {
	for _, ascending := range []bool{false, true} {
		lines := []string{"and x1,x0,#8", "add x1,x1,#8"}
		update := "subs x1,x1,#8"
		want := arm64PoolInterval{8, 16}
		if ascending {
			lines = append(lines, "negs x1,x1")
			update, want = "adds x1,x1,#8", arm64PoolInterval{^uint64(15), ^uint64(7)}
		}
		head := len(lines)
		lines = append(lines, "nop", update, "b.ne #-8", "ret")
		flow := arm64PoolTestFlow(t, lines)
		if got := flow.affineInterval(head, arm64PoolRegisterExpression(1)); got != want {
			t.Fatalf("ascending=%v: counter bound=%+v, want %+v", ascending, got, want)
		}
	}
}

func TestARM64PoolCounterStrideRoundsProvedResidue(t *testing.T) {
	for _, ascending := range []bool{false, true} {
		lines := []string{"and x1,x0,#8", "add x1,x1,#8"}
		initial, want, delta := arm64PoolInterval{1, 19}, arm64PoolInterval{8, 16}, ^uint64(7)
		if ascending {
			lines = append(lines, "neg x1,x1")
			initial = arm64PoolInterval{^uint64(18), ^uint64(0)}
			want, delta = arm64PoolInterval{^uint64(15), ^uint64(7)}, 8
		}
		at := len(lines)
		flow := arm64PoolTestFlow(t, append(lines, "ret"))
		got, proved := flow.counterStrideBound(at, arm64PoolRegisterExpression(1), initial, delta)
		if !proved || got != want {
			t.Fatalf("ascending=%v: residue-refined bound=%+v proved=%v, want %+v", ascending, got, proved, want)
		}
	}
}

func TestARM64PoolCounterResidueMasks(t *testing.T) {
	for _, test := range []struct {
		lines []string
		want  bool
	}{
		{[]string{"and x1,x0,#24"}, true},
		{[]string{"ands x1,x0,#24"}, true},
		{[]string{"mov x2,#24", "and x1,x0,x2"}, true},
		{[]string{"mov x2,#12", "and x1,x0,x2,lsl #1"}, true},
		{[]string{"mov x2,#48", "ands x1,x0,x2,lsr #1"}, true},
		{[]string{"mov x2,#48", "and x1,x0,x2,asr #1"}, true},
		{[]string{"mov x2,#12", "and x1,x0,x2,ror #63"}, true},
		{[]string{"mov x2,#7", "bic x1,x0,x2"}, true},
		{[]string{"mov x2,#14", "bics x1,x0,x2,lsr #1"}, true},
		{[]string{"mov x2,#14", "bic x1,x0,x2,asr #1"}, true},
		{[]string{"mov x2,#14", "bic x1,x0,x2,ror #1"}, true},
		{[]string{"and x1,x0,#24", "str x1,[sp,#8]", "ldr x1,[sp,#8]"}, true},
		{[]string{"and x1,x0,#24", "and x1,x1,#15"}, true},
		{[]string{"and x1,x0,#7"}, false},
		{[]string{"mov x2,#7", "bic x1,x0,x2,lsl #1"}, false},
		{[]string{"and x1,x0,x2"}, false},
		{[]string{"and w1,w0,#24"}, false},
		{[]string{"adr x1,#0"}, false},
		{[]string{"and x1,x0,#24", "add x1,x1,#1"}, false},
		{[]string{"and x1,x0,#24", "str x1,[sp,#8]", "str x2,[sp,#8]", "ldr x1,[sp,#8]"}, false},
	} {
		lines := append(append([]string(nil), test.lines...), "ret")
		flow := arm64PoolTestFlow(t, lines)
		flow.clearValueCaches()
		if got := flow.multipleOfPowerOfTwo(len(test.lines), arm64PoolRegisterExpression(1), 8); got != test.want {
			t.Errorf("%v: divisible=%v, want %v", test.lines, got, test.want)
		}
		flow.affineWork = 16384
		if flow.multipleOfPowerOfTwo(len(test.lines), arm64PoolRegisterExpression(1), 8) {
			t.Fatal("exhausted residue budget became a successful proof")
		}
	}
}

func TestARM64PoolCounterStrideRejectsUnprovedResidues(t *testing.T) {
	for _, prefix := range [][]string{
		{"and x1,x0,#7", "add x1,x1,#8"},
		{"and x1,x0,#8"},
		{"and x1,x0,#8", "add x1,x1,#9"},
		{"and x1,x0,#8", "add x1,x1,#8", "add x1,x1,x2"},
		{"and x1,x0,#8", "add x1,x1,#8", "str x1,[sp,#8]", "str x2,[sp,#8]", "ldr x1,[sp,#8]"},
	} {
		head := len(prefix)
		lines := append(append([]string(nil), prefix...), "nop", "sub x1,x1,#8", "cbnz x1,#-8", "ret")
		flow := arm64PoolTestFlow(t, lines)
		if _, proved := flow.loopBounds[head]; proved {
			t.Fatalf("unproved residue accepted: %v", prefix)
		}
	}
}
