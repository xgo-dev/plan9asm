package plan9asm

import (
	"fmt"
	"math"
	"testing"
)

func TestARM64PoolDisjointLogicalBounds(t *testing.T) {
	for _, op := range []string{"orr", "eor"} {
		for _, source := range []struct {
			operand string
			value   int
			want    arm64PoolInterval
		}{
			{"x2", 16, arm64PoolInterval{16, 17}},
			{"x2, lsl #4", 1, arm64PoolInterval{16, 17}},
			{"x2, lsr #1", 32, arm64PoolInterval{16, 17}},
			{"x2, asr #1", 32, arm64PoolInterval{16, 17}},
			{"x2, ror #63", 8, arm64PoolInterval{16, 17}},
			{"#16", 0, arm64PoolInterval{16, 17}},
		} {
			line := fmt.Sprintf("%s x3, x1, %s", op, source.operand)
			t.Run(line, func(t *testing.T) {
				flow := arm64PoolTestFlow(t, []string{
					"and x1, x0, #1", fmt.Sprintf("mov x2, #%d", source.value), line, "ret",
				})
				if got := flow.affineInterval(3, arm64PoolRegisterExpression(3)); got != source.want {
					t.Fatalf("logical result=%+v, want %+v", got, source.want)
				}
			})
		}
	}
}

func TestARM64PoolPartialMaskBounds(t *testing.T) {
	flow := arm64PoolTestFlow(t, []string{"and x1, x0, #1", "add x2, x1, #16", "ret"})
	if got := flow.affineInterval(2, arm64PoolRegisterExpression(2)); got != (arm64PoolInterval{16, 17}) {
		t.Fatalf("nonconstant mask lost its range: %+v", got)
	}
}

func TestARM64PoolLogicalBoundsDoNotInventRelations(t *testing.T) {
	for _, op := range []string{"orr", "eor"} {
		flow := arm64PoolTestFlow(t, []string{
			"and x1, x0, #3", "and x2, x0, #3", op + " x3, x1, x2", "ret",
		})
		value, span, affine, known := flow.affineLogicalDefinition(2, flow.words[2])
		if !known || affine || span != (arm64PoolInterval{0, 3}) {
			t.Fatalf("%s overlapping bits: value=%+v span=%+v affine=%v known=%v",
				op, value, span, affine, known)
		}
		if got := flow.affineInterval(3, arm64PoolRegisterExpression(3)); got != span {
			t.Fatalf("%s lost conservative bit bounds: %+v", op, got)
		}
	}
	flow := arm64PoolTestFlow(t, []string{"orr w3, w1, w2", "ret"})
	if _, _, _, known := flow.affineLogicalDefinition(0, flow.words[0]); known {
		t.Fatal("a truncating W operation became an X affine definition")
	}
	flow = arm64PoolTestFlow(t, []string{
		"cbz x0, #12", "and x1, x2, #1", "b #8", "and x1, x2, #16", "ret",
	})
	if got := flow.affineInterval(4, arm64PoolRegisterExpression(1)); got != (arm64PoolInterval{0, 16}) {
		t.Fatalf("one predecessor's bound leaked into another: %+v", got)
	}
}

func TestARM64PoolLogicalBitsAreNotRelocatedOffsets(t *testing.T) {
	for _, test := range []struct {
		line string
		want arm64PoolInterval
	}{
		{"and x1, x0, #15", arm64PoolInterval{0, 15}},
		{"orr x1, x0, #16", arm64PoolInterval{16, math.MaxUint64}},
		{"eor x1, x0, #16", arm64PoolUnknownInterval},
	} {
		flow := arm64PoolTestFlow(t, []string{"adr x0, #8", test.line, "ret"})
		flow.poolOrigins = map[int]uint64{0: 8}
		if got := flow.affineInterval(2, arm64PoolRegisterExpression(1)); got != test.want {
			t.Fatalf("%s used an offset as address bits: %+v, want %+v", test.line, got, test.want)
		}
	}
}

func TestARM64PoolLogicalShiftBitBounds(t *testing.T) {
	for _, base := range []uint64{0, 31, 1 << 63, math.MaxUint64 - 31} {
		for width := uint64(0); width < 16; width++ {
			must, may := arm64PoolIntervalBits(arm64PoolInterval{base, base + width})
			for kind := uint32(0); kind < 4; kind++ {
				for _, amount := range []uint32{0, 1, 4, 30, 31, 32, 63} {
					operand := arm64PoolLogicalOperand{
						must: must, may: may, value: arm64PoolRegisterExpression(1), affine: true,
					}.shifted(kind, amount)
					for n := uint64(0); n <= width; n++ {
						value := base + n
						var shifted uint64
						switch kind {
						case 0:
							shifted = value << amount
						case 1:
							shifted = value >> amount
						case 2:
							shifted = uint64(int64(value) >> amount)
						case 3:
							shifted = value>>amount | value<<((64-amount)&63)
						}
						if shifted&operand.must != operand.must || shifted&^operand.may != 0 {
							t.Fatalf("shift %d/%d excluded %x: %+v", kind, amount, shifted, operand)
						}
						if operand.affine && operand.value.constant+uint64(operand.value.coefficient[1])*value != shifted {
							t.Fatalf("shift %d/%d invented affine value: %+v", kind, amount, operand)
						}
					}
				}
			}
		}
	}
}
