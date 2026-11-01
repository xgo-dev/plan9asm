//go:build unix && go1.27

package plan9asm

import (
	"fmt"
	"testing"
)

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalExchange(t *testing.T) {
	assembly, declarations, rows := fixedLocalExchangeProgram(t)
	inputs := []uint64{0, 1, ^uint64(0), 0x0123456789abcdef}
	var expected [][]string
	for _, input := range inputs {
		var values []string
		for _, row := range rows {
			values = append(values, fmt.Sprintf("%016x", row.want(input)))
		}
		expected = append(expected, values)
	}
	fixedLocalResultsRuntime(t, assembly, declarations, inputs, expected)
}
