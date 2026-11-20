package plan9asm

import "testing"

// This is a required native-AMD64 axis. Rosetta numeric diagnostics do not
// establish precision traps or the original memory instruction's fault rules.
func TestCrossLinuxRuntimeMatrixX86SignedPackedIntegerFloatNativeReadAndPrecisionFaults(t *testing.T) {
	runX86SignedPackedIntegerFloatNativeReadAndPrecisionFaults(t)
}
