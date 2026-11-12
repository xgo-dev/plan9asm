//go:build go1.27

package plan9asm

import (
	"fmt"
	"testing"
)

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalVEXLogicalZero(t *testing.T) {
	// The Y-width integer identities require AVX2. The existing native probe
	// checks the CPU, OS register state and actual AVX2 execution before Go.
	fixedLocalVEXNativeTools(t)
	assembly, declarations, count := fixedLocalVEXZeroProgram(t)
	inputs := []uint64{0, 1, ^uint64(0), 0x0123456789abcdef}
	var expected [][]string
	for _, input := range inputs {
		values := make([]string, count)
		for index := range values {
			// All four Y qwords must be zero, including an X result's upper
			// alias. Only the independently stored input canary contributes.
			values[index] = fmt.Sprintf("%016x", input)
		}
		expected = append(expected, values)
	}
	fixedLocalResultsRuntimeISA(t, assembly, declarations, inputs, expected, x86FloatCompareVEX)
}
