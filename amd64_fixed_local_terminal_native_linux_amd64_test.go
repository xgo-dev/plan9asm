//go:build go1.27

package plan9asm

import (
	"fmt"
	"testing"
)

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalTerminalReturns(t *testing.T) {
	assembly, declarations := fixedLocalTerminalReturnProgram()
	inputs := []uint64{0, 1, 2, ^uint64(0)}
	var expected [][]string
	for range inputs {
		expected = append(expected, []string{"0000000000000007", "0000000000000007"})
	}
	fixedLocalResultsRuntime(t, assembly, declarations, inputs, expected)
	t.Log("native terminal inventory: functions=2 inputs=4 observations_per_program=8 APIs=3 optimizations=2 execute=true")
}

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalLayoutPartitions(t *testing.T) {
	assembly, declarations := fixedLocalLayoutPartitionProgram()
	inputs := []uint64{0, 1, 2, 3, 4, 9, 16}
	var expected [][]string
	for _, input := range inputs {
		value := fmt.Sprintf("%016x", input+1)
		expected = append(expected, []string{value, value, value})
	}
	fixedLocalResultsRuntime(t, assembly, declarations, inputs, expected)
	t.Log("native private-layout inventory: functions=3 inputs=7 observations_per_program=21 APIs=3 optimizations=2 execute=true")
}
