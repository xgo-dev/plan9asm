package plan9asm

import (
	"math"

	"golang.org/x/arch/arm64/arm64asm"
)

// Normalize the eight signed/unsigned ordered conditions to smaller <= larger,
// with an inclusive flag distinguishing <= from <. The induction below proves
// both operands nonnegative and below the sign bit; only in that common domain
// are the signed and unsigned comparisons interchangeable.
func (flow *arm64RawPoolValues) orderedLoopCompare(latch int) (smaller, larger int, inclusive, ok bool) {
	word := flow.words[latch]
	if word&0xff000010 != 0x54000000 {
		return
	}
	compare, clobbered, valid := flow.affineFlagsBefore(latch)
	if !valid || compare&0xffe0fc1f != 0xeb00001f {
		return // CMP Xn, Xm, without a shift or an extension.
	}
	smaller, larger = int(compare>>5&31), int(compare>>16&31)
	if smaller == 31 || larger == 31 || smaller == larger ||
		clobbered&((1<<uint(smaller))|(1<<uint(larger))) != 0 {
		return
	}
	switch word & 15 {
	case 3, 11: // LO, LT
	case 9, 13: // LS, LE
		inclusive = true
	case 8, 12: // HI, GT
		smaller, larger = larger, smaller
	case 2, 10: // HS, GE
		smaller, larger, inclusive = larger, smaller, true
	default:
		return
	}
	ok = true
	return
}

func (flow *arm64RawPoolValues) proveOrderedCounterLoop(latch int) {
	smaller, larger, inclusive, ok := flow.orderedLoopCompare(latch)
	if !ok {
		return
	}
	head := latch + int(int32(flow.words[latch]<<8)>>13)
	for _, counter := range []int{smaller, larger} {
		_, delta, valid := flow.counterLoopUpdate(head, latch, counter)
		if !valid || counter == smaller && delta != 1 || counter == larger && delta != math.MaxUint64 {
			continue
		}
		limit := smaller
		if counter == smaller {
			limit = larger
		}
		unchanged := true
		for at := head; at < latch; at++ {
			writes, known := arm64RawPoolGPWrites(flow.words[at])
			unchanged = unchanged && known && writes&(1<<uint(limit)) == 0
		}
		if !unchanged {
			continue
		}
		entry := flow.counterLoopEntry(head, latch)
		if entry == nil {
			continue
		}
		first := entry.integerInterval(head, arm64asm.X0+arm64asm.Reg(counter))
		last := entry.integerInterval(head, arm64asm.X0+arm64asm.Reg(limit))
		if first.high > math.MaxInt64 || last.high > math.MaxInt64 {
			continue
		}
		// Inclusive loops execute once at equality, then step past the limit.
		// Prove that final update cannot wrap or cross the signed boundary.
		if inclusive && (counter == smaller && last.high == math.MaxInt64 ||
			counter == larger && last.low == 0) {
			continue
		}
		remaining := arm64PoolRegisterExpression(larger)
		remaining.add(arm64PoolRegisterExpression(smaller), -1)
		initial := entry.affineInterval(head, remaining)
		minimum := uint64(1)
		if inclusive {
			minimum = 0
		}
		if initial.low < minimum || initial.high > math.MaxInt64 {
			continue
		}
		if flow.loopBounds == nil {
			flow.loopBounds = make(map[int]arm64PoolConstraint)
		}
		flow.loopBounds[head] = arm64PoolConstraint{
			expression: remaining, interval: arm64PoolInterval{minimum, initial.high},
		}
		flow.recordLoopLatch(head, latch)
		flow.clearValueCaches()
		return
	}
}
