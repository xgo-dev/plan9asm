//go:build unix && go1.27

package plan9asm

import "testing"

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalAliasedFrame(t *testing.T) {
	assembly, declarations, expected := fixedLocalAliasedFrameProgram()
	if len(expected) != 30 {
		t.Fatal("complete aliased frame runtime inventory changed", len(expected))
	}
	fixedLocalConstantResultsRuntime(t, assembly, declarations, expected)
}
