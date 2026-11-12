//go:build unix

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func fixedLocalBlockRuntimeKernels() []fixedLocalVEXRuntimeKernel {
	var kernels []fixedLocalVEXRuntimeKernel
	for _, name := range []string{"VINSERTF128", "VINSERTI128", "VEXTRACTF128", "VEXTRACTI128"} {
		for _, selector := range []int{0, 1, 254, 255} {
			prefix := fmt.Sprintf("%s $%d,", name, selector)
			var operations []string
			if strings.HasPrefix(name, "VINSERT") {
				for _, source := range []string{"X0", "64(BP)", "65(BP)", "0(SI)", "1(SI)"} {
					operations = append(operations, prefix+source+",Y1,Y2")
				}
				operations = append(operations, prefix+"X0,Y1,Y0", prefix+"X0,Y1,Y1", prefix+"X0,Y0,Y0")
			} else {
				for _, destination := range []string{"X2", "X1", "64(BP)", "65(BP)", "0(SI)", "1(SI)"} {
					operations = append(operations, prefix+"Y1,"+destination)
				}
			}
			kernels = append(kernels, fixedLocalVEXRuntimeKernel{shape: operations[0], operations: operations})
		}
	}
	return kernels
}

func TestGoAMD64FixedLocalBlockTransferRuntimeObjects(t *testing.T) {
	kernels := fixedLocalBlockRuntimeKernels()
	if len(kernels) != 16 {
		t.Fatal("block-transfer runtime inventory changed", len(kernels))
	}
	fixedLocalVectorRuntime(t, fixedLocalPackedCompileOnlyTools(t), false, kernels)
}
