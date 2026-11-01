package plan9asm

import "testing"

func TestCrossLinuxRuntimeMatrixX86PackedMoveAlignedMaskedMemory(t *testing.T) {
	x86PackedMoveMaskedMemoryRuntime(t, true)
}

func TestCrossLinuxRuntimeMatrixX86PackedMoveAlignedRegisterViews(t *testing.T) {
	x86PackedMoveRegisterViewsRuntime(t, true)
}

func TestCrossLinuxRuntimeMatrixX86PackedMoveAlignedOriginalGo(t *testing.T) {
	x86PackedMoveObservableRuntime(t, true, true)
}
