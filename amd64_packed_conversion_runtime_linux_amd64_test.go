package plan9asm

import "testing"

// This required owner is separate from Rosetta SSE and object-only evidence.
// CPUID/OS-state and original-opcode preflight must execute successfully.
func TestCrossLinuxRuntimeMatrixX86PackedConversionNativeAVX512Status(t *testing.T) {
	x86PackedConversionCompleteNativeValues(t, 0)
}

func TestCrossLinuxRuntimeMatrixX86PackedConversionNativeIndependentC(t *testing.T) {
	amd64PackedNumericConversionNativeRuntimeSemantics(t)
}

func TestCrossLinuxRuntimeMatrixX86PackedConversionNativeDeadFaults(t *testing.T) {
	x86PackedConversionCompleteNativeFaults(t, 0)
}

func TestCrossLinuxRuntimeMatrixX86PackedConversionNativeAVX512StatusPart1(t *testing.T) {
	x86PackedConversionCompleteNativeValues(t, 1)
}

func TestCrossLinuxRuntimeMatrixX86PackedConversionNativeAVX512StatusPart2(t *testing.T) {
	x86PackedConversionCompleteNativeValues(t, 2)
}

func TestCrossLinuxRuntimeMatrixX86PackedConversionNativeAVX512StatusPart3(t *testing.T) {
	x86PackedConversionCompleteNativeValues(t, 3)
}

func TestCrossLinuxRuntimeMatrixX86PackedConversionNativeAVX512StatusPart4(t *testing.T) {
	x86PackedConversionCompleteNativeValues(t, 4)
}

func TestCrossLinuxRuntimeMatrixX86PackedConversionNativeAVX512StatusPart5(t *testing.T) {
	x86PackedConversionCompleteNativeValues(t, 5)
}

func TestCrossLinuxRuntimeMatrixX86PackedConversionNativeAVX512StatusPart6(t *testing.T) {
	x86PackedConversionCompleteNativeValues(t, 6)
}

func TestCrossLinuxRuntimeMatrixX86PackedConversionNativeAVX512StatusPart7(t *testing.T) {
	x86PackedConversionCompleteNativeValues(t, 7)
}

func TestCrossLinuxRuntimeMatrixX86PackedConversionNativeDeadFaultsPart1(t *testing.T) {
	x86PackedConversionCompleteNativeFaults(t, 1)
}

func TestCrossLinuxRuntimeMatrixX86PackedConversionNativeDeadFaultsPart2(t *testing.T) {
	x86PackedConversionCompleteNativeFaults(t, 2)
}

func TestCrossLinuxRuntimeMatrixX86PackedConversionNativeDeadFaultsPart3(t *testing.T) {
	x86PackedConversionCompleteNativeFaults(t, 3)
}

func TestCrossLinuxRuntimeMatrixX86PackedConversionNativeDeadFaultsPart4(t *testing.T) {
	x86PackedConversionCompleteNativeFaults(t, 4)
}

func TestCrossLinuxRuntimeMatrixX86PackedConversionNativeDeadFaultsPart5(t *testing.T) {
	x86PackedConversionCompleteNativeFaults(t, 5)
}

func TestCrossLinuxRuntimeMatrixX86PackedConversionNativeDeadFaultsPart6(t *testing.T) {
	x86PackedConversionCompleteNativeFaults(t, 6)
}

func TestCrossLinuxRuntimeMatrixX86PackedConversionNativeDeadFaultsPart7(t *testing.T) {
	x86PackedConversionCompleteNativeFaults(t, 7)
}
