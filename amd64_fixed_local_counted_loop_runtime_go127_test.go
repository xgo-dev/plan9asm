//go:build unix && go1.27

package plan9asm

import (
	"encoding/binary"
	"fmt"
	"testing"
)

func fixedLocalCountedLoopRuntimeInputs() []uint64 {
	// Both low-bit values exercise one and two outer passes. The remaining
	// values distinguish wrapped arithmetic and overlapping byte stores.
	return []uint64{0, 1, ^uint64(0), ^uint64(0) - 1, 0x0123456789abcdef}
}

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalCountedLoop(t *testing.T) {
	assembly, declarations, inventory := fixedLocalCountedLoopProgram(t)
	if len(inventory) != 38 {
		t.Fatal("counted-loop runtime inventory changed", len(inventory))
	}
	inputs := fixedLocalCountedLoopRuntimeInputs()
	var expected [][]string
	for _, input := range inputs {
		var values []string
		for _, row := range fixedLocalCountedLoopCases() {
			values = append(values, fmt.Sprintf("%016x", uint64(row.iterations)*(input+2)+77))
		}
		expected = append(expected, append(values, "64686c7074787c80", "64686c7074787c80"))
	}
	fixedLocalResultsRuntime(t, assembly, declarations, inputs, expected)
}

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalCountedLoopAliases(t *testing.T) {
	assembly, declarations, cases := fixedLocalCountedLoopAliasProgram(t)
	inputs := fixedLocalCountedLoopRuntimeInputs()
	var expected [][]string
	for _, input := range inputs {
		var values []string
		for _, row := range cases {
			// This byte-array oracle preserves earlier stores that overlap
			// later iterations; retaining only the last access gives a
			// different result for these nonuniform input bytes.
			var memory [32]byte
			for _, offset := range row.offsets {
				binary.LittleEndian.PutUint64(memory[offset:], input+uint64(offset)+2)
			}
			sum := uint64(77)
			for _, offset := range row.offsets {
				sum += binary.LittleEndian.Uint64(memory[offset:])
			}
			values = append(values, fmt.Sprintf("%016x", sum))
		}
		expected = append(expected, values)
	}
	fixedLocalResultsRuntime(t, assembly, declarations, inputs, expected)
}
