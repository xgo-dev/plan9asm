//go:build linux && amd64 && plan9asm_native_avx512

package plan9asm

import "testing"

// CPUID/OS-state preflight and complete native fixtures remain required.
func TestCrossLinuxRuntimeMatrixX86RawScalarFloatToIntegerNative(t *testing.T) {
	x86RawScalarFloatToIntegerNativeRuntime(t)
}

func TestCrossLinuxRuntimeMatrixX86ScalarFloatIntegerNativeVectorMatrix(t *testing.T) {
	x86ScalarFloatIntegerNumericalMatrix(t, true)
}

func TestCrossLinuxRuntimeMatrixX86ScalarFloatIntegerNativeVectorDeadFaults(t *testing.T) {
	x86ScalarFloatIntegerDeadFaults(t, true, true)
}
