package plan9asm

import "testing"

func TestCrossLinuxRuntimeMatrixX86PackedMoveUnalignedOriginalGo(t *testing.T) {
	x86PackedMoveUnalignedRuntime(t, true)
}
