package plan9asm

import "testing"

func TestCrossLinuxRuntimeMatrixX86COMINativeVectorFlags(t *testing.T) {
	t.Run("VEX", func(t *testing.T) {
		x86ScalarCompareAFOriginalGo(t, x86FloatCompareVEX)
		x86ScalarCompareAFLLVM(t, x86FloatCompareVEX)
	})
}

func TestCrossLinuxRuntimeMatrixX86COMINativeVectorMXCSR(t *testing.T) {
	t.Run("VEX", func(t *testing.T) {
		x86COMIOriginalConstantsAndMXCSR(t, x86FloatCompareVEX)
	})
}
