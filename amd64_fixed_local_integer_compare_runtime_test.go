//go:build unix

package plan9asm

import (
	"strings"
	"testing"
)

func fixedLocalIntegerCompareRuntimeKernels(t *testing.T) []fixedLocalVEXRuntimeKernel {
	t.Helper()
	var kernels []fixedLocalVEXRuntimeKernel
	owners := make(map[string]int)
	rows := fixedLocalIntegerCompareCases()
	for _, row := range rows {
		parts := strings.Split(row.name, "/")
		shape := parts[0] + "/" + parts[1]
		index, exists := owners[shape]
		if !exists {
			index, owners[shape] = len(kernels), len(kernels)
			kernels = append(kernels, fixedLocalVEXRuntimeKernel{shape: shape})
		}
		// Observe defined CMP FLAGS after each comparison, including AF via
		// LAHF, in scratch bytes outside all comparison input ranges.
		operation := "MOVQ (SI),AX\nCMPQ AX,$1\n" + row.operation +
			"\nLAHF\nMOVB AH,120(BP)\nSETOS 121(BP)"
		if strings.Contains(row.name, "unknown self") {
			// The common oracle observes Y0..Y3. Expose each high-bank result
			// without reading undefined legacy upper bytes; VEX defines them.
			if row.legacy {
				operation += "\nMOVOU " + row.destination + ",X2"
			} else {
				operation += "\nVMOVDQU " + strings.Replace(row.destination, "X", "Y", 1) + ",Y2"
			}
		}
		kernels[index].operations = append(kernels[index].operations, operation)
	}
	if len(kernels) != 24 || len(rows) != 168 {
		t.Fatal("comparison runtime family/width/operand inventory changed", len(kernels), len(rows))
	}
	return kernels
}

func TestGoAMD64FixedLocalIntegerCompareRuntimeObjects(t *testing.T) {
	fixedLocalVectorRuntime(t, fixedLocalPackedCompileOnlyTools(t), false, fixedLocalIntegerCompareRuntimeKernels(t))
}
