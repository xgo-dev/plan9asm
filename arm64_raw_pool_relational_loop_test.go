package plan9asm

import (
	"fmt"
	"testing"
)

func TestARM64PoolOneIterationRelations(t *testing.T) {
	for _, test := range []struct {
		name, step, compare string
		base                int
		body                []string
		want                bool
	}{
		{"compare", "16", "cmp x1,x3", 16, nil, true},
		{"reversed", "16", "cmp x3,x1", 16, nil, true},
		{"retained-result", "16", "subs x5,x1,x3", 16, nil, true},
		{"preserved-flags", "16", "cmp x1,x3", 16, []string{"mov x1,#99"}, true},
		{"wrong-step", "15", "cmp x1,x3", 16, nil, false},
		{"multiple-iterations", "16", "cmp x1,x3", 32, nil, false},
		{"underflow", "16", "cmp x1,x3", 0, nil, false},
		{"other-limit", "16", "cmp x1,x0", 16, nil, false},
		{"word-flags", "16", "cmp w1,w3", 16, nil, false},
		{"clobbered-flags", "16", "cmp x1,x3", 16, []string{"tst x0,x0"}, false},
		{"changed-limit-and-flags", "16", "cmp x1,x3", 16, []string{"adds x3,x3,#1"}, false},
		{"unknown-effects", "16", "cmp x1,x3", 16, []string{"udf #0"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			lines := []string{"and x1,x0,#3", fmt.Sprintf("add x1,x1,#%d", test.base),
				"mov x2,#15", "and x3,x1,x2", "mov x4,#" + test.step}
			head := len(lines)
			lines = append(lines, "sub x1,x1,x4", test.compare)
			lines = append(lines, test.body...)
			latch := len(lines)
			lines = append(lines, fmt.Sprintf("b.ne #%d", (head-latch)*4), "ret")
			flow := arm64PoolTestFlow(t, lines)
			if got := flow.excluded[arm64RawPoolEdge{latch, head}]; got != test.want {
				t.Fatalf("excluded one-iteration backedge=%v, want %v", got, test.want)
			}
		})
	}
}

func TestARM64PoolRelationalLoopEntries(t *testing.T) {
	for _, sideEntry := range []bool{false, true} {
		lines := []string{"and x1,x0,#3", "add x1,x1,#16", "mov x2,#15", "and x3,x1,x2", "mov x4,#16"}
		if sideEntry {
			lines = append(lines, "cbz x0,#8")
		}
		head := len(lines)
		lines = append(lines, "sub x1,x1,x4", "cmp x1,x3", "b.ne #-8")
		latch := len(lines) - 1
		if !sideEntry {
			lines = append(lines, "add x1,x1,#32", fmt.Sprintf("b #%d", (head-len(lines)-1)*4))
		} else {
			lines = append(lines, "ret")
		}
		flow := arm64PoolTestFlow(t, lines)
		if flow.excluded[arm64RawPoolEdge{latch, head}] {
			t.Fatalf("side-entry=%v: ignored an unproved incoming iteration", sideEntry)
		}
	}
}
