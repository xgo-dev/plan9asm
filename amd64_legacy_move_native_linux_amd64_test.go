package plan9asm

import "testing"

// Unlike Rosetta diagnostics, this required native CI axis also compares the
// original aligned-SSE faults for every nonzero misalignment.
func TestCrossLinuxRuntimeMatrixX86LegacyMoveNativeAlignment(t *testing.T) {
	x86LegacyMoveNativeRuntime(t, true)
}
