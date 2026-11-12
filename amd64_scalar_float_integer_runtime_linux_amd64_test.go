package plan9asm

import "testing"

func TestCrossLinuxRuntimeMatrixX86ScalarFloatIntegerNativeLegacyUnmaskedTraps(t *testing.T) {
	x86ScalarFloatIntegerDeadFaults(t, false, true)
}
