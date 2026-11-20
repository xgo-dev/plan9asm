//go:build linux && amd64 && plan9asm_native_avx512

package plan9asm

import "testing"

func TestCrossLinuxRuntimeMatrixX86COMIRawNativeCompare(t *testing.T) {
	x86COMIRawNativeCompare(t)
}

func TestCrossLinuxRuntimeMatrixX86COMINativeDeadExceptions(t *testing.T) {
	x86COMIDeadFaults(t, true)
}

func TestCrossLinuxRuntimeMatrixX86COMINativeVectorFlagsEVEX(t *testing.T) {
	t.Run("EVEX", func(t *testing.T) {
		x86ScalarCompareAFOriginalGo(t, x86FloatCompareEVEX)
		x86ScalarCompareAFLLVM(t, x86FloatCompareEVEX)
	})
}

func TestCrossLinuxRuntimeMatrixX86COMINativeVectorMXCSREVEX(t *testing.T) {
	t.Run("EVEX", func(t *testing.T) {
		x86COMIOriginalConstantsAndMXCSR(t, x86FloatCompareEVEX)
	})
}
