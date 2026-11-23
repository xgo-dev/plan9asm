package plan9asm

import (
	"fmt"
	"math/bits"
)

// Native SIMD constraints carry a whole V register. Validated instruction
// forms select the scalar subregister or the active vector arrangement.
func arm64NativeSIMDReg(index int, arrangement arm64VectorArrangement) string {
	bank := arm64NativeSIMDBank(arrangement.elementBits)
	if arrangement.lanes == 1 {
		return fmt.Sprintf("${%d:%c}", index, bank)
	}
	return fmt.Sprintf("$%d.%d%c", index, arrangement.lanes, bank)
}

func arm64NativeSIMDBank(elementBits int) byte {
	return "bhsd"[bits.TrailingZeros(uint(elementBits))-3]
}
