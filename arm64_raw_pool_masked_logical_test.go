package plan9asm

import (
	"fmt"
	"math"
	"testing"
)

func TestARM64PoolMaskedLogicalRelations(t *testing.T) {
	for _, test := range []struct {
		line string
		mask uint64
	}{
		{"and x3,x1,x2", 15},
		{"and x3,x2,x1", 15},
		{"and x3,x1,#15", 0},
		{"and x3,x1,x2,lsl #1", 7},
		{"and x3,x1,x2,lsr #1", 30},
		{"and x3,x1,x2,asr #1", 30},
		{"and x3,x1,x2,ror #63", 1<<63 | 7},
		{"bic x3,x1,x2", ^uint64(15)},
		{"bic x3,x1,x2,lsl #1", ^uint64(6)},
		{"bic x3,x1,x2,lsr #1", math.MaxUint64 - 31},
		{"bic x3,x1,x2,asr #1", math.MaxUint64 - 31},
		{"bic x3,x1,x2,ror #63", ^uint64(1<<63 | 7)},
	} {
		t.Run(test.line, func(t *testing.T) {
			flow := arm64PoolTestFlow(t, []string{
				"and x1,x0,#3", "add x1,x1,#16",
				fmt.Sprintf("mov x2,#%#x", test.mask), test.line, "ret",
			})
			value, span, affine, known := flow.affineLogicalDefinition(3, flow.words[3])
			if !known {
				t.Fatalf("masked logical form was not modeled: %s", test.line)
			}
			// LSL produces a mask that drops one variable bit: it must retain
			// bounds without pretending the result is an affine displacement.
			shifted := test.line == "and x3,x1,x2,lsl #1" || test.line == "bic x3,x1,x2,lsl #1"
			want := arm64PoolInterval{0, 3}
			if shifted {
				want.high = 2
				if test.line == "bic x3,x1,x2,lsl #1" {
					want.high = 1
				}
			}
			if span != want || affine == shifted {
				t.Fatalf("result=%+v affine=%v, want %+v affine=%v", span, affine, want, !shifted)
			}
			if affine {
				expected := arm64PoolRegisterExpression(1)
				expected.constant = math.MaxUint64 - 15
				if value != expected {
					t.Fatalf("lost n & mask = n - 16 relationship: %+v", value)
				}
			}
		})
	}
}

func TestARM64PoolMaskedAffineConcreteValues(t *testing.T) {
	for _, base := range []uint64{0, 16, 31, 1 << 63, math.MaxUint64 - 31} {
		for width := uint64(0); width < 16; width++ {
			must, may := arm64PoolIntervalBits(arm64PoolInterval{base, base + width})
			operand := arm64PoolLogicalOperand{
				must: must, may: may, value: arm64PoolRegisterExpression(1), affine: true,
			}
			for _, mask := range []uint64{0, 1, 7, 15, 16, 24, 255, 1 << 63, math.MaxUint64} {
				value, affine := operand.maskedAffine(arm64PoolLogicalOperand{must: mask, may: mask})
				if !affine {
					continue
				}
				for n := base; n <= base+width; n++ {
					if got := uint64(value.coefficient[1])*n + value.constant; got != n&mask {
						t.Fatalf("mask=%#x n=%#x produced %#x from %+v", mask, n, got, value)
					}
				}
			}
		}
	}
}

func TestARM64PoolMaskedLogicalUnknownAndRelocatedValues(t *testing.T) {
	for _, op := range []string{"and", "bic"} {
		flow := arm64PoolTestFlow(t, []string{op + " x3,x1,x2", "ret"})
		_, span, affine, known := flow.affineLogicalDefinition(0, flow.words[0])
		if !known || affine || span != arm64PoolUnknownInterval {
			t.Fatalf("%s invented a relation for unknown operands: %+v/%v/%v", op, span, affine, known)
		}
		flow = arm64PoolTestFlow(t, []string{op + " w3,w1,w2", "ret"})
		if _, _, _, known := flow.affineLogicalDefinition(0, flow.words[0]); known {
			t.Fatalf("%s truncating W form became an X relation", op)
		}
	}
	flow := arm64PoolTestFlow(t, []string{"adr x1,#12", "mov x2,#15", "and x3,x1,x2", "ret"})
	flow.poolOrigins = map[int]uint64{0: 16}
	_, span, affine, known := flow.affineLogicalDefinition(2, flow.words[2])
	if !known || affine || span != (arm64PoolInterval{0, 15}) {
		t.Fatalf("pool offset became numeric address bits: %+v/%v/%v", span, affine, known)
	}
}
