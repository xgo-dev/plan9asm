//go:build linux && (amd64 || arm64)

package plan9asm

import "testing"

func TestCrossLinuxRuntimeMatrixX86FloatingCompareFPScalarByteSpansVEX(t *testing.T) {
	x86FloatCompareFPScalarByteSpansRuntime(t, x86FloatCompareVEX)
}

func TestCrossLinuxRuntimeMatrixX86FloatingCompareIndependentIEEEAndMXCSRVEX(t *testing.T) {
	x86FloatCompareIndependentRuntime(t, x86FloatCompareVEX)
}

func TestCrossLinuxRuntimeMatrixX86FloatingCompareDeadResultEffectsVEX(t *testing.T) {
	x86FloatCompareDeadResultRuntime(t, x86FloatCompareVEX)
}
