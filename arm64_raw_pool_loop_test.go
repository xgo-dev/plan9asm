package plan9asm

import (
	"fmt"
	"testing"
)

func arm64PoolTestFlow(t *testing.T, lines []string) *arm64RawPoolValues {
	t.Helper()
	words := assembleARM64LLVMWords(t, lines, "")
	instructions := make([]Instr, len(words))
	reachable := make(map[int]bool)
	for at, word := range words {
		instructions[at] = Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}}
		reachable[at] = true
	}
	return newARM64RawPoolValues(instructions, 0, len(words), reachable)
}

func TestARM64PoolCounterLoops(t *testing.T) {
	for _, test := range []struct {
		name  string
		lines []string
		at    int
		want  arm64PoolInterval
	}{
		{"countdown-cbnz", []string{
			"and x1, x1, #7", "cbz x1, #20", "nop", "sub x1, x1, #1",
			"nop", "cbnz x1, #-12", "ret",
		}, 2, arm64PoolInterval{1, 7}},
		{"countdown-preserved-flags", []string{
			"and x1, x1, #7", "cbz x1, #20", "nop", "subs x1, x1, #1",
			"orr w2, w2, w3", "b.ne #-12", "ret",
		}, 2, arm64PoolInterval{1, 7}},
		{"one-negative-step", []string{
			"mov x1, #-8", "nop", "add x1, x1, #8", "cbnz x1, #-8", "ret",
		}, 2, arm64PoolInterval{^uint64(7), ^uint64(7)}},
		{"one-positive-step", []string{
			"mov x1, #16", "nop", "sub x1, x1, #16", "cbnz x1, #-8", "ret",
		}, 2, arm64PoolInterval{16, 16}},
		{"zero-entry-wraps", []string{
			"and x1, x1, #7", "nop", "sub x1, x1, #1", "cbnz x1, #-8", "ret",
		}, 1, arm64PoolUnknownInterval},
		{"wrong-step-can-wrap", []string{
			"mov x1, #7", "nop", "sub x1, x1, #2", "cbnz x1, #-8", "ret",
		}, 1, arm64PoolUnknownInterval},
		{"clobbered-flags", []string{
			"mov x1, #7", "nop", "subs x1, x1, #1", "cmp x2, #0", "b.ne #-12", "ret",
		}, 1, arm64PoolUnknownInterval},
		{"multiple-writes", []string{
			"mov x1, #7", "nop", "sub x1, x1, #1", "add x1, x1, x2", "cbnz x1, #-12", "ret",
		}, 1, arm64PoolUnknownInterval},
		{"side-entry", []string{
			"cbz x2, #16", "mov x1, #7", "nop", "sub x1, x1, #1", "nop", "cbnz x1, #-12", "ret",
		}, 2, arm64PoolUnknownInterval},
		{"word-test-not-x-bound", []string{
			"mov x1, #7", "nop", "sub x1, x1, #1", "cbnz w1, #-8", "ret",
		}, 1, arm64PoolUnknownInterval},
		{"enclosing-loop-changes-entry", []string{
			"mov x2, #1", "mov x1, #2", "nop", "sub x1, x1, #1", "add x2, x2, #1",
			"cbnz x1, #-12", "mov x1, x2", "b #-20",
		}, 2, arm64PoolUnknownInterval},
	} {
		t.Run(test.name, func(t *testing.T) {
			flow := arm64PoolTestFlow(t, test.lines)
			if got := flow.affineInterval(test.at, arm64PoolRegisterExpression(1)); got != test.want {
				t.Fatalf("counter interval = %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestARM64PoolExcludedBackedgeDropsInductionMetadata(t *testing.T) {
	flow := arm64PoolTestFlow(t, []string{
		"and x1,x0,#8", "add x1,x1,#8", "nop", "sub x1,x1,#8", "cbnz x1,#-8", "ret",
	})
	if _, proved := flow.loopBounds[2]; !proved {
		t.Fatal("fixture did not establish a counter loop")
	}
	flow.excludeEdge(arm64RawPoolEdge{4, 2})
	if _, retained := flow.loopBounds[2]; retained {
		t.Fatal("excluded backedge retained its induction constraint")
	}
	if _, retained := flow.loopLatches[2]; retained {
		t.Fatal("excluded backedge retained its carried-value latch")
	}
}

func TestARM64PoolImpossibleBitEdge(t *testing.T) {
	// The backwards TBNZ edge is impossible for 16..19, but its MOV would
	// otherwise pollute the joined result before the query becomes constant.
	flow := arm64PoolTestFlow(t, []string{
		"cmp x1, #16", "b.lo #36", "cmp x1, #19", "b.hi #28", "b #12",
		"mov x2, #99", "b #12", "mov x2, #8", "tbnz w1, #3, #-12", "nop", "ret",
	})
	if got := flow.affineInterval(9, arm64PoolRegisterExpression(2)); got != (arm64PoolInterval{8, 8}) {
		t.Fatalf("impossible edge polluted value: %+v", got)
	}
}

func TestARM64PoolCounterLoopInvariantResidual(t *testing.T) {
	flow := arm64PoolTestFlow(t, []string{
		"mov x2, #64", "mov x1, #7", "add x3, x2, x1, lsl #3",
		"subs x1, x1, #1", "b.ne #-8", "ret",
	})
	if got := flow.affineInterval(3, arm64PoolRegisterExpression(3)); got != (arm64PoolInterval{72, 120}) {
		t.Fatalf("invariant residual lost: %+v", got)
	}
}

func TestARM64PoolCounterLoopLongPreservedFlags(t *testing.T) {
	for _, clobber := range []bool{false, true} {
		t.Run(fmt.Sprintf("clobber=%v", clobber), func(t *testing.T) {
			lines := []string{"mov x1, #7", "nop", "subs x1, x1, #1"}
			for i := 0; i < 12; i++ {
				lines = append(lines, "ext v0.16b, v1.16b, v2.16b, #8", "uxtl v3.4s, v4.4h",
					"cmhi v5.8b, v6.8b, v7.8b", "mul x2, x3, x4")
			}
			if clobber {
				lines[20] = "tst x2, x3"
			}
			lines = append(lines, fmt.Sprintf("b.ne #%d", (1-len(lines))*4), "ret")
			flow := arm64PoolTestFlow(t, lines)
			want := arm64PoolInterval{1, 7}
			if clobber {
				want = arm64PoolUnknownInterval
			}
			if got := flow.affineInterval(1, arm64PoolRegisterExpression(1)); got != want {
				t.Fatalf("counter = %+v, want %+v", got, want)
			}
		})
	}
}
