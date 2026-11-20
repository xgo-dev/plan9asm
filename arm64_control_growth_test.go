package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func arm64ControlGrowthValue(targets int) arm64ControlValue {
	value := arm64ControlExternal()
	for index := 0; index < targets; index++ {
		next := arm64ControlFromMap(map[string]bool{fmt.Sprintf("label:continuation_%d", index): true})
		value = arm64ControlUnion(value, next)
	}
	return value
}

func arm64ControlGrowthCheckValue(tb testing.TB, value arm64ControlValue, targets int) {
	tb.Helper()
	if arm64ControlCount(value) != targets+1 || !arm64ControlHas(value, "") {
		tb.Fatalf("wrong complete target set: %d entries, want %d", arm64ControlCount(value), targets+1)
	}
	for index := 0; index < targets; index++ {
		if !arm64ControlHas(value, fmt.Sprintf("label:continuation_%d", index)) {
			tb.Fatalf("missing original continuation %d", index)
		}
	}
}

func arm64ControlGrowthFixture(calls, cells int) (Func, error) {
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT controlGrowth(SB),4,$%d-0\nMOVD R30,R19\n", (cells+2)*8)
	for cell := 0; cell < cells; cell++ {
		fmt.Fprintf(&source, "MOVD R30,%d(RSP)\n", (cell+1)*8)
	}
	for call := 0; call < calls; call++ {
		fmt.Fprintf(&source, "call_%d:\nCALL external(SB)\n", call)
	}
	source.WriteString("done:\nMOVD R19,R30\nRET\n")
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		return Func{}, err
	}
	return file.Funcs[0], nil
}

func arm64ControlGrowthContext(fn Func) *arm64Ctx {
	return &arm64Ctx{
		blocks:           arm64SplitBlocks(fn),
		normalizedSource: fn,
		sig:              FuncSig{Name: "controlGrowth", Ret: Void},
		resolve:          func(name string) string { return name },
	}
}

func arm64ControlGrowthCheckPlan(tb testing.TB, ctx *arm64Ctx, calls int) {
	tb.Helper()
	plan := ctx.localControl
	if plan == nil || len(plan.reachable) != len(ctx.blocks) {
		tb.Fatal("missing complete control plan")
	}
	for block, reachable := range plan.reachable {
		if !reachable {
			tb.Fatalf("lost original block %d", block)
		}
	}
	var value arm64ControlValue
	for block, body := range ctx.blocks {
		for instruction, ins := range body.instrs {
			if ins.Op == OpRET {
				value = plan.linkBefore[[2]int{block, instruction}]
				ctx.currentInstruction = instruction
				if err := ctx.requireCallerLinkRestored(block, ins); !errors.Is(err, ErrProbeNeedsContext) {
					tb.Fatalf("unproved native calls gained caller permission: %v", err)
				}
			}
		}
	}
	expected := arm64ControlFromMap(map[string]bool{"": true, "label:" + plan.outer: true, "label:done": true})
	for call := 1; call < calls; call++ {
		expected = arm64ControlSetToken(expected, fmt.Sprintf("label:call_%d", call), true)
	}
	if !arm64ControlEqual(value, expected) {
		tb.Fatalf("changed original complete return targets: got %v, want %v", value, expected)
	}
}

func TestARM64ControlGrowingContinuationAllocation(t *testing.T) {
	const targets = 512
	result := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for iteration := 0; iteration < b.N; iteration++ {
			value := arm64ControlGrowthValue(targets)
			arm64ControlGrowthCheckValue(b, value, targets)
		}
	})
	t.Logf("complete %d-target growing query: %s %s", targets, result, result.MemString())
	// This is a first-party allocation regression, not an analysis limit or
	// target cap. Every original token above must remain present.
	if result.AllocedBytesPerOp() > 2<<20 {
		t.Fatalf("growing query repeatedly copies complete prior token maps: %d bytes/op", result.AllocedBytesPerOp())
	}
}

func TestARM64ControlGrowthCompleteNativeCalls(t *testing.T) {
	fn, err := arm64ControlGrowthFixture(8, 16)
	if err != nil {
		t.Fatal(err)
	}
	ctx := arm64ControlGrowthContext(fn)
	if err := ctx.prepareLocalControl(); err != nil {
		t.Fatal(err)
	}
	arm64ControlGrowthCheckPlan(t, ctx, 8)
}

func TestARM64ControlGrowthActualGoObjects(t *testing.T) {
	for _, size := range []struct{ calls, cells int }{{8, 16}, {512, 256}} {
		t.Run(fmt.Sprintf("calls_%d_cells_%d", size.calls, size.cells), func(t *testing.T) {
			fn, err := arm64ControlGrowthFixture(size.calls, size.cells)
			if err != nil {
				t.Fatal(err)
			}
			var source strings.Builder
			for _, instruction := range fn.Instrs {
				source.WriteString(instruction.Raw + "\n")
			}
			goAssemblerOracleOutput(t, "arm64", source.String(), "", true)
			t.Logf("actual selected Go object source SHA256 %x; unknown native calls retain Context", sha256.Sum256([]byte(source.String())))
		})
	}
}

func BenchmarkARM64ControlGrowingUnion(b *testing.B) {
	for _, targets := range []int{256, 512, 1024} {
		b.Run(fmt.Sprintf("targets_%d", targets), func(b *testing.B) {
			b.ReportAllocs()
			for iteration := 0; iteration < b.N; iteration++ {
				value := arm64ControlGrowthValue(targets)
				arm64ControlGrowthCheckValue(b, value, targets)
			}
		})
	}
}

func BenchmarkARM64ControlOuterStateClone(b *testing.B) {
	for _, cells := range []int{128, 256, 512} {
		b.Run(fmt.Sprintf("cells_%d", cells), func(b *testing.B) {
			state := arm64ControlSharingState(512)
			for cell := 0; cell < cells; cell++ {
				state.memory[fmt.Sprintf("sp:%d", cell*8)] = state.escaped
			}
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				copy := state.clone()
				if len(copy.memory) != cells || !arm64ControlEqual(copy.escaped, state.escaped) {
					b.Fatal("outer clone changed complete state")
				}
			}
		})
	}
}

func BenchmarkARM64ControlGrowingNativeCFG(b *testing.B) {
	for _, size := range []struct{ calls, cells int }{{128, 64}, {256, 128}, {512, 256}} {
		b.Run(fmt.Sprintf("calls_%d_cells_%d", size.calls, size.cells), func(b *testing.B) {
			fn, err := arm64ControlGrowthFixture(size.calls, size.cells)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				ctx := arm64ControlGrowthContext(fn)
				if err := ctx.prepareLocalControl(); err != nil {
					b.Fatal(err)
				}
				arm64ControlGrowthCheckPlan(b, ctx, size.calls)
			}
		})
	}
}
