package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestGoAMD64FixedLocalLargeLinearFrameState(t *testing.T) {
	for _, shape := range []string{"linear", "diamond"} {
		t.Run(shape, func(t *testing.T) {
			fn, sig := fixedLocalReplayFixture(t, fixedLocalReplayBody(shape, 1600))
			fn.FrameSize = 1408
			if fn.FrameSize*int64(len(fn.Instrs)) <= 1<<20 {
				t.Fatal("fixture no longer exceeds the old per-instruction state estimate")
			}
			if _, err := proveX86FixedLocal(fn, sig); err != nil {
				t.Fatal("long basic blocks must not reserve a frame state per instruction", err)
			}
		})
	}
}

func fixedLocalRetainedStateBudgetFixture(t *testing.T) (Func, FuncSig) {
	t.Helper()
	var body strings.Builder
	for index := 0; index < 20; index++ {
		fmt.Fprintf(&body, "CMPQ AX,AX\nJEQ next%d\nNOP\nnext%d:\n", index, index)
	}
	fn, sig := fixedLocalReplayFixture(t, body.String())
	fn.FrameSize = 64 << 10
	return fn, sig
}

func TestGoAMD64FixedLocalRetainedStateBudgetIsAtomic(t *testing.T) {
	fn, sig := fixedLocalRetainedStateBudgetFixture(t)
	proof := &x86FixedLocalProof{frame: fn.FrameSize}
	budget := x86FixedLocalBudget{steps: 1 << 18, bytes: 64 << 20}
	err := replayX86FixedLocal(&fn, sig, proof, 0, &budget, nil, nil)
	if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "state storage budget") {
		t.Fatal("actual retained frame states exceeded the storage cap", err)
	}
	if budget.steps <= 0 || budget.bytes <= 0 {
		t.Fatal("fixture must hit retained storage before the independent work budgets")
	}
	for _, ins := range fn.Instrs {
		if len(ins.x86FixedLocalMemory) != 0 {
			t.Fatal("state-budget failure published a provisional access")
		}
	}
}
