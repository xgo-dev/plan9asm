//go:build unix && go1.27

package plan9asm

import "testing"

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalReturnCFG(t *testing.T) {
	assembly, declarations, expected := fixedLocalReturnCFGProgram()
	if len(expected) != 4 {
		t.Fatal("complete return CFG runtime inventory changed", len(expected))
	}
	fixedLocalConstantResultsRuntime(t, assembly, declarations, expected)
}
