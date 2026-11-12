package plan9asm

import (
	"fmt"
	"testing"
)

func TestARM64PoolMoveWideConstants(t *testing.T) {
	for _, width := range []int{32, 64} {
		for shift := 0; shift < width; shift += 16 {
			for _, immediate := range []uint64{0, 0x1234, 0xffff} {
				name := fmt.Sprintf("%d/shift%d/%x", width, shift, immediate)
				t.Run(name, func(t *testing.T) {
					register := "x1"
					initial := uint64(0x0123456789abcdef)
					if width == 32 {
						register = "w1"
						initial = uint64(uint32(initial))
					}
					lines := []string{
						"mov x1, #0xcdef", "movk x1, #0x89ab, lsl #16",
						"movk x1, #0x4567, lsl #32", "movk x1, #0x123, lsl #48",
						fmt.Sprintf("movk %s, #%d, lsl #%d", register, immediate, shift), "ret",
					}
					flow := arm64PoolTestFlow(t, lines)
					want := initial&^(uint64(0xffff)<<uint(shift)) | immediate<<uint(shift)
					if got := flow.affineInterval(5, arm64PoolRegisterExpression(1)); got != (arm64PoolInterval{want, want}) {
						t.Fatalf("wide constant = %+v, want %x", got, want)
					}
				})
			}
		}
	}
}

func TestARM64PoolMoveWideInvariantAndCompleteOverwrite(t *testing.T) {
	for _, initial := range []string{"mov x1, #0xcdef", "movk x1, #0xcdef"} {
		lines := []string{initial, "movk x1, #0x89ab, lsl #16",
			"movk x1, #0x4567, lsl #32", "movk x1, #0x123, lsl #48",
			"add x2, x2, #1", "cmp x2, x0", "b.ne #-8", "ret"}
		flow := arm64PoolTestFlow(t, lines)
		want := arm64PoolInterval{0x0123456789abcdef, 0x0123456789abcdef}
		if got := flow.invariantInterval(7, arm64PoolRegisterExpression(1)); got != want {
			t.Fatalf("materialized invariant %q=%+v", initial, got)
		}
	}
}
