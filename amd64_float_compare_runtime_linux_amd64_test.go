package plan9asm

import "testing"

func TestCrossLinuxRuntimeMatrixX86FloatingCompareFPScalarByteSpansEVEX(t *testing.T) {
	x86FloatCompareFPScalarByteSpansRuntime(t, x86FloatCompareEVEX)
}

func TestCrossLinuxRuntimeMatrixX86FloatingCompareIndependentIEEEAndMXCSREVEX(t *testing.T) {
	x86FloatCompareIndependentRuntime(t, x86FloatCompareEVEX)
}

func TestCrossLinuxRuntimeMatrixX86FloatingCompareDeadResultEffectsEVEX(t *testing.T) {
	x86FloatCompareDeadResultRuntime(t, x86FloatCompareEVEX)
}

func TestCrossLinuxRuntimeMatrixAMD64ConformanceNativeAVX512(t *testing.T) {
	execution := x86FloatCompareRuntimeTools(t, x86FloatCompareEVEX)
	amd64ConformanceOriginalWideGo(t, execution)
	amd64ConformanceLLVMRuntime(t, execution, true)
}
