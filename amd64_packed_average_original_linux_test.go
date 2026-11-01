//go:build linux

package plan9asm

import "testing"

// Required by the existing Linux cross-matrix selector. Its actual AVX
// preflight and pinned guest transport must fail, not skip, if unavailable.
func TestCrossLinuxRuntimeMatrixX86PackedAverageOriginalVEXAliases(t *testing.T) {
	x86AverageOriginalGo(t, true)
}
