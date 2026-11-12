package plan9asm

import "testing"

func x86PackedReductionRequireNativeHost(t *testing.T) {
	t.Helper()
}

func TestCrossLinuxRuntimeMatrixX86PackedReductionNativeValuesPart0(t *testing.T) {
	x86PackedReductionNativeValues(t, 0)
}

func TestCrossLinuxRuntimeMatrixX86PackedReductionNativeValuesPart1(t *testing.T) {
	x86PackedReductionNativeValues(t, 1)
}

func TestCrossLinuxRuntimeMatrixX86PackedReductionNativeValuesPart2(t *testing.T) {
	x86PackedReductionNativeValues(t, 2)
}

func TestCrossLinuxRuntimeMatrixX86PackedReductionNativeValuesPart3(t *testing.T) {
	x86PackedReductionNativeValues(t, 3)
}

func TestCrossLinuxRuntimeMatrixX86PackedReductionNativeDeadFaultsPart0(t *testing.T) {
	x86PackedReductionNativeFaults(t, 0)
}

func TestCrossLinuxRuntimeMatrixX86PackedReductionNativeDeadFaultsPart1(t *testing.T) {
	x86PackedReductionNativeFaults(t, 1)
}

func TestCrossLinuxRuntimeMatrixX86PackedReductionNativeDeadFaultsPart2(t *testing.T) {
	x86PackedReductionNativeFaults(t, 2)
}

func TestCrossLinuxRuntimeMatrixX86PackedReductionNativeDeadFaultsPart3(t *testing.T) {
	x86PackedReductionNativeFaults(t, 3)
}
