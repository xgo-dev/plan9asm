package plan9asm

import (
	"fmt"
	"math"
	"math/bits"
	"testing"
)

func arm64PoolMaterialize(register string, value uint64) []string {
	lines := []string{fmt.Sprintf("mov %s, #%d", register, value&0xffff)}
	for shift := uint(16); shift < 64; shift += 16 {
		lines = append(lines, fmt.Sprintf("movk %s, #%d, lsl #%d", register, value>>shift&0xffff, shift))
	}
	return lines
}

func TestARM64PoolExactDivisionRemainders(t *testing.T) {
	for _, test := range []struct {
		divisor, multiplier uint64
		pre, post           uint
	}{
		{3, 0xaaaaaaaaaaaaaaab, 0, 1},
		{5, 0xcccccccccccccccd, 0, 2},
		{10, 0xcccccccccccccccd, 0, 3},
		{100, 0x28f5c28f5c28f5c3, 2, 2},
		{8, 0x8000000000000000, 2, 0},
	} {
		for _, swapped := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/swap=%v", test.divisor, swapped), func(t *testing.T) {
				lines := arm64PoolMaterialize("x15", test.multiplier)
				lines = append(lines, fmt.Sprintf("mov x16, #%d", test.divisor), "mov x21, x0",
					fmt.Sprintf("lsr x7, x0, #%d", test.pre), "umulh x7, x7, x15",
					fmt.Sprintf("lsr x7, x7, #%d", test.post))
				subtract := "msub x22, x7, x16, x21"
				if swapped {
					lines[7] = "umulh x7, x15, x7"
					subtract = "msub x22, x16, x7, x21"
				}
				lines = append(lines, subtract, "ret")
				flow := arm64PoolTestFlow(t, lines)
				want := arm64PoolInterval{0, test.divisor - 1}
				if got := flow.affineInterval(len(lines)-1, arm64PoolRegisterExpression(22)); got != want {
					t.Fatalf("remainder=%+v, want %+v", got, want)
				}
			})
		}
	}
	flow := arm64PoolTestFlow(t, []string{
		"mov x2, #7", "udiv x3, x0, x2", "msub x4, x3, x2, x0", "ret",
	})
	if got := flow.affineInterval(3, arm64PoolRegisterExpression(4)); got != (arm64PoolInterval{0, 6}) {
		t.Fatalf("direct division remainder=%+v", got)
	}
}

func TestARM64PoolShiftedGuardPreimage(t *testing.T) {
	flow := arm64PoolTestFlow(t, []string{
		"lsr x2, x1, #4", "cmp x2, #624", "b.hi #12", "mov x3, x1", "nop", "ret",
	})
	if got := flow.affineInterval(4, arm64PoolRegisterExpression(3)); got != (arm64PoolInterval{0, 9999}) {
		t.Fatalf("right-shift guard preimage=%+v", got)
	}
}

func TestARM64PoolReciprocalQuotientUnderExitGuard(t *testing.T) {
	lines := arm64PoolMaterialize("x15", 0x28f5c28f5c28f5c3)
	lines = append(lines, "mov x21, x0", "lsr x7, x0, #2", "umulh x7, x7, x15",
		"lsr x7, x7, #2", "lsr x21, x21, #4", "cmp x21, #624", "b.hi #8", "nop", "ret")
	flow := arm64PoolTestFlow(t, lines)
	if got := flow.affineInterval(11, arm64PoolRegisterExpression(7)); got != (arm64PoolInterval{0, 99}) {
		t.Fatalf("guarded quotient=%+v", got)
	}
}

func TestARM64PoolQuotientGuardDoesNotConstrainOldNumerator(t *testing.T) {
	flow := arm64PoolTestFlow(t, []string{
		"mov x2, #3", "udiv x0, x0, x2", "cmp x0, #10", "b.hi #8", "nop", "ret",
	})
	if got := flow.affineInterval(4, arm64PoolRegisterExpression(0)); got != (arm64PoolInterval{0, 10}) {
		t.Fatalf("quotient guard was applied to its old input: %+v", got)
	}
}

func TestARM64PoolReciprocalProofArithmetic(t *testing.T) {
	state := uint64(0x9e3779b97f4a7c15)
	next := func() uint64 {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		return state
	}
	proved := 0
	for n := 0; n < 10000; n++ {
		multiplier, pre, post := next(), uint(next()%64), uint(next()%64)
		divisor, ok := arm64PoolReciprocalDivisor(multiplier, pre, post)
		if !ok {
			continue
		}
		proved++
		for _, input := range []uint64{0, 1, divisor - 1, divisor, math.MaxUint64, next(), next()} {
			high, _ := bits.Mul64(input>>pre, multiplier)
			if got := high >> post; got != input/divisor {
				t.Fatalf("invalid reciprocal proof: m=%x pre=%d post=%d d=%d n=%d q=%d", multiplier, pre, post, divisor, input, got)
			}
		}
	}
	if proved == 0 {
		t.Fatal("reciprocal arithmetic test exercised no accepted proof")
	}
	for _, test := range []struct {
		multiplier uint64
		pre, post  uint
	}{
		{0, 0, 0}, {0xaaaaaaaaaaaaaaab, 64, 1}, {0xaaaaaaaaaaaaaaab, 0, 64},
		{0xaaaaaaaaaaaaaaaa, 0, 1}, {0xaaaaaaaaaaaaaaac, 0, 1},
		{0x28f5c28f5c28f5c3, 0, 2},
	} {
		if divisor, ok := arm64PoolReciprocalDivisor(test.multiplier, test.pre, test.post); ok {
			t.Fatalf("invalid reciprocal parameters accepted as divisor %d: %+v", divisor, test)
		}
	}
}

func TestARM64PoolRejectsInvalidRemainderIdentities(t *testing.T) {
	for _, test := range []struct {
		name                      string
		multiplier                uint64
		divisor                   int
		multiply, extra, subtract string
	}{
		{"rounded-down", 0xaaaaaaaaaaaaaaaa, 3, "umulh", "nop", "msub x22, x7, x16, x21"},
		{"too-large", 0xaaaaaaaaaaaaaaac, 3, "umulh", "nop", "msub x22, x7, x16, x21"},
		{"signed-high", 0xaaaaaaaaaaaaaaab, 3, "smulh", "nop", "msub x22, x7, x16, x21"},
		{"wrong-divisor", 0xaaaaaaaaaaaaaaab, 4, "umulh", "nop", "msub x22, x7, x16, x21"},
		{"changed-numerator", 0xaaaaaaaaaaaaaaab, 3, "umulh", "add x21, x21, #1", "msub x22, x7, x16, x21"},
		{"changed-quotient", 0xaaaaaaaaaaaaaaab, 3, "umulh", "add x7, x7, #1", "msub x22, x7, x16, x21"},
		{"truncated-product", 0xaaaaaaaaaaaaaaab, 3, "umulh", "nop", "msub w22, w7, w16, w21"},
	} {
		t.Run(test.name, func(t *testing.T) {
			lines := arm64PoolMaterialize("x15", test.multiplier)
			lines = append(lines, fmt.Sprintf("mov x16, #%d", test.divisor), "mov x21, x0",
				test.multiply+" x7, x0, x15", "lsr x7, x7, #1", test.extra, test.subtract, "ret")
			flow := arm64PoolTestFlow(t, lines)
			if got := flow.affineInterval(len(lines)-1, arm64PoolRegisterExpression(22)); got != arm64PoolUnknownInterval {
				t.Fatalf("invalid remainder identity accepted: %+v", got)
			}
		})
	}
	for _, shift := range []string{"lsr w2, w1, #4", "lsr x2, x1, #4"} {
		flow := arm64PoolTestFlow(t, []string{
			shift, "cmp x2, #624", "mov x1, x0", "b.hi #8", "nop", "ret",
		})
		if got := flow.affineInterval(4, arm64PoolRegisterExpression(1)); got != arm64PoolUnknownInterval {
			t.Fatalf("shift guard bounded an unrelated replacement: %+v", got)
		}
	}
}
