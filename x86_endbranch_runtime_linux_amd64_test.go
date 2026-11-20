package plan9asm

import "testing"

func TestCrossLinuxRuntimeMatrixX86EndBranchNativeState(t *testing.T) {
	TestX86RawEndBranchRuntimePreservesState(t)
}
