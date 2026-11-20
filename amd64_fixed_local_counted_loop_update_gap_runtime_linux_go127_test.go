//go:build linux && (amd64 || arm64) && go1.27

package plan9asm

import (
	"fmt"
	"testing"
)

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalCountedLoopUpdateGap(t *testing.T) {
	assembly, declarations, count := fixedLocalCountedLoopUpdateGapProgram(t)
	inputs := fixedLocalCountedLoopRuntimeInputs()
	var expected [][]string
	for _, input := range inputs {
		values := make([]string, count)
		for index := range values {
			values[index] = fmt.Sprintf("%016x", input+2)
		}
		expected = append(expected, values)
	}
	// Original Go executes the Y-register moves. Require actual AVX and
	// enabled OS register state before either source program runs.
	fixedLocalResultsRuntimeISA(t, assembly, declarations, inputs, expected, x86FloatCompareVEX)
}
