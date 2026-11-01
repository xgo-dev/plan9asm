package plan9asm

import "testing"

// EVEX requires actual native AMD64 plus CPUID/OS-state preflight. The
// portable five-target object gate is not counted as native execution.
func TestCrossLinuxRuntimeMatrixX86RawScalarFloatToIntegerNative(t *testing.T) {
	x86RawScalarFloatToIntegerNativeRuntime(t)
}

func TestCrossLinuxRuntimeMatrixX86ScalarFloatIntegerNativeVectorMatrix(t *testing.T) {
	x86ScalarFloatIntegerNumericalMatrix(t, true)
}

func TestCrossLinuxRuntimeMatrixX86ScalarFloatIntegerNativeVectorDeadFaults(t *testing.T) {
	x86ScalarFloatIntegerDeadFaults(t, true, true)
}

func TestCrossLinuxRuntimeMatrixX86ScalarFloatIntegerNativeLegacyUnmaskedTraps(t *testing.T) {
	x86ScalarFloatIntegerDeadFaults(t, false, true)
}
