//go:build linux && amd64 && plan9asm_native_avx512

package plan9asm

import "testing"

func TestCrossLinuxRuntimeMatrixX86PackedMoveUnalignedOriginalGo(t *testing.T) {
	x86PackedMoveUnalignedRuntime(t, true)
}
