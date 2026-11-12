package plan9asm

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Object/analysis only: unknown external code is never linked or executed.
// A shared helper receives growing return sets and writes the exact same set
// into every original private cell, matching the retained workload dimension.
func arm64ControlRepeatedHelperSource(calls, cells int) string {
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT repeatedHelper(SB),4,$%d-0\nMOVD R30,R19\n", (cells+2)*8)
	for call := 0; call < calls; call++ {
		fmt.Fprintf(&source, "call_%d:\nCALL helper\n", call)
	}
	source.WriteString("done:\nMOVD R19,R30\nRET\nhelper:\n")
	for cell := 0; cell < cells; cell++ {
		fmt.Fprintf(&source, "MOVD R30,%d(RSP)\n", (cell+1)*8)
	}
	source.WriteString("MOVD R30,R20\nCALL external(SB)\nMOVD R20,R30\nRET\n")
	return source.String()
}

func arm64ControlRepeatedHelperContext(tb testing.TB, calls, cells int) (*arm64Ctx, string) {
	tb.Helper()
	source := arm64ControlRepeatedHelperSource(calls, cells)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		tb.Fatal(err)
	}
	fn := file.Funcs[0]
	return &arm64Ctx{
		blocks: arm64SplitBlocks(fn), normalizedSource: fn,
		sig: FuncSig{Name: "repeatedHelper", Ret: Void}, resolve: func(name string) string { return name },
	}, source
}

func arm64ControlRepeatedHelperCheck(tb testing.TB, ctx *arm64Ctx, calls int) {
	tb.Helper()
	plan := ctx.localControl
	if plan == nil || len(plan.reachable) != len(ctx.blocks) {
		tb.Fatal("missing complete growing helper plan")
	}
	for _, reachable := range plan.reachable {
		if !reachable {
			tb.Fatal("dropped original reachable helper/return block")
		}
	}
	for call := 1; call < calls; call++ {
		token := fmt.Sprintf("label:call_%d", call)
		found := false
		for _, value := range plan.linkBefore {
			found = found || arm64ControlHas(value, token)
		}
		if !found {
			tb.Fatalf("dropped original return destination %q", token)
		}
	}
}

func TestARM64ControlRepeatedHelperCompleteSourceReceipts(t *testing.T) {
	for _, size := range []struct{ calls, cells int }{{8, 16}, {32, 32}} {
		t.Run(fmt.Sprintf("calls_%d_cells_%d", size.calls, size.cells), func(t *testing.T) {
			ctx, source := arm64ControlRepeatedHelperContext(t, size.calls, size.cells)
			goAssemblerOracleOutput(t, "arm64", source, "", true)
			if err := ctx.prepareLocalControl(); err != nil {
				t.Fatal(err)
			}
			arm64ControlRepeatedHelperCheck(t, ctx, size.calls)
			type point struct {
				Block, Instruction  int
				Before, Stack, Link arm64ControlValue
			}
			var points []point
			for block, body := range ctx.blocks {
				for instruction := range body.instrs {
					key := [2]int{block, instruction}
					points = append(points, point{block, instruction, ctx.localControl.before[key],
						ctx.localControl.stackBefore[key], ctx.localControl.linkBefore[key]})
				}
			}
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, translateErr := Translate(file, Options{
				Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
				Sigs: map[string]FuncSig{"repeatedHelper": {Name: "repeatedHelper", Ret: Void}},
			})
			if !errors.Is(translateErr, ErrProbeNeedsContext) || ir != "" {
				t.Fatalf("unknown external helper gained native/ABI authority: %v", translateErr)
			}
			receipt := struct {
				Source, Outer, Diagnostic, IR string
				Original                      Func
				Reachable                     []bool
				AutoFrame                     bool
				Points                        []point
			}{source, ctx.localControl.outer, translateErr.Error(), ir, file.Funcs[0],
				ctx.localControl.reachable, ctx.localControl.autoFrame, points}
			encoded, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("repeated-helper-complete-receipt %s", encoded)
		})
	}
}

func BenchmarkARM64ControlRepeatedHelperCFG(b *testing.B) {
	for _, size := range []struct{ calls, cells int }{{32, 16}, {128, 64}, {512, 256}} {
		b.Run(fmt.Sprintf("calls_%d_cells_%d", size.calls, size.cells), func(b *testing.B) {
			prototype, _ := arm64ControlRepeatedHelperContext(b, size.calls, size.cells)
			fn := prototype.normalizedSource
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				ctx := &arm64Ctx{
					blocks: arm64SplitBlocks(fn), normalizedSource: fn,
					sig: prototype.sig, resolve: prototype.resolve,
				}
				if err := ctx.prepareLocalControl(); err != nil {
					b.Fatal(err)
				}
				arm64ControlRepeatedHelperCheck(b, ctx, size.calls)
			}
		})
	}
}
