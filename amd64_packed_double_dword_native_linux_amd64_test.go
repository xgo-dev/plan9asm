//go:build linux && amd64 && plan9asm_native_avx512

package plan9asm

import "testing"

func TestCrossLinuxRuntimeMatrixAMD64PackedDoubleDwordNativeAVX512(t *testing.T) {
	execution := x86PackedDoubleDwordNativeTools(t)
	x86PackedDoubleDwordOriginalGo(t, execution)
	amd64PackedDoubleDwordRuntime(t, execution, true)
}
