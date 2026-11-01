package plan9asm

import "testing"

func TestCrossLinuxRuntimeMatrixX86COMIRawNativeCompare(t *testing.T) {
	x86COMIRawNativeCompare(t)
}

func TestCrossLinuxRuntimeMatrixX86COMINativeDeadExceptions(t *testing.T) {
	x86COMIDeadFaults(t, true)
}

func TestCrossLinuxRuntimeMatrixX86COMINativeVectorFlags(t *testing.T) {
	for _, axis := range []x86FloatCompareRuntimeISA{x86FloatCompareVEX, x86FloatCompareEVEX} {
		t.Run(map[x86FloatCompareRuntimeISA]string{x86FloatCompareVEX: "VEX", x86FloatCompareEVEX: "EVEX"}[axis], func(t *testing.T) {
			x86ScalarCompareAFOriginalGo(t, axis)
			x86ScalarCompareAFLLVM(t, axis)
		})
	}
}

func TestCrossLinuxRuntimeMatrixX86COMINativeVectorMXCSR(t *testing.T) {
	for _, axis := range []x86FloatCompareRuntimeISA{x86FloatCompareVEX, x86FloatCompareEVEX} {
		t.Run(map[x86FloatCompareRuntimeISA]string{x86FloatCompareVEX: "VEX", x86FloatCompareEVEX: "EVEX"}[axis], func(t *testing.T) {
			x86COMIOriginalConstantsAndMXCSR(t, axis)
		})
	}
}
