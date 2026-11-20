package plan9asm

import (
	"reflect"
	"strings"
	"testing"
)

func arm64StackAllocationContext(t testing.TB, count int) *arm64Ctx {
	t.Helper()
	source := "TEXT allocation(SB),$0-0\n" + strings.Repeat("MOVD $1,R0\n", count) + "RET\n"
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	return &arm64Ctx{blocks: arm64SplitBlocks(file.Funcs[0])}
}

func TestARM64StackProofAllocationDoesNotScaleWithReadOnlyOperands(t *testing.T) {
	measure := func(count int) float64 {
		ctx := arm64StackAllocationContext(t, count)
		return testing.AllocsPerRun(5, func() {
			low, high, err := ctx.stackMovementRange()
			if err != nil || low != 0 || high != 0 {
				t.Fatalf("stack bounds [%d,%d]: %v", low, high, err)
			}
		})
	}
	small, large := measure(1), measure(256)
	if large > small+8 {
		t.Fatalf("read-only instructions added %.0f allocations: small=%.0f large=%.0f", large-small, small, large)
	}
}

func TestARM64StackProofIndexedWritebackKeepsSourceImmutable(t *testing.T) {
	file, err := Parse(ArchARM64, "TEXT zero_writeback(SB),$0-0\nVST1.P [V0.B16],(RSP)(R7)\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	ctx := &arm64Ctx{blocks: arm64SplitBlocks(file.Funcs[0])}
	var source *Instr
	for i := range ctx.blocks {
		for j := range ctx.blocks[i].instrs {
			if ctx.blocks[i].instrs[j].Op == "VST1.P" {
				source = &ctx.blocks[i].instrs[j]
			}
		}
	}
	if source == nil {
		t.Fatal("missing indexed writeback instruction")
	}
	want := append([]Operand(nil), source.Args...)
	for attempt := 0; attempt < 3; attempt++ {
		if _, _, err := ctx.stackMovementRange(); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(source.Args, want) {
			t.Fatalf("stack proof mutated source operands: got %+v, want %+v", source.Args, want)
		}
	}
}

func BenchmarkARM64StackProofReadOnlyOperands(b *testing.B) {
	ctx := arm64StackAllocationContext(b, 4096)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := ctx.stackMovementRange(); err != nil {
			b.Fatal(err)
		}
	}
}
