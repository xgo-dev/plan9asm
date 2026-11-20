//go:build linux && (amd64 || arm64)

package plan9asm

import "testing"

// This mandatory axis executes the translated actual whole VEX compare against
// the independent original opcode. QEMU has AVX/AVX2 but not native AVX512.
func TestCrossLinuxRuntimeMatrixX86FloatingCompareVEXWholeIEEEAndMXCSR(t *testing.T) {
	x86FloatCompareVEXWholeRuntime(t)
}
