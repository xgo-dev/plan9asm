//go:build linux && amd64 && plan9asm_native_avx512

package plan9asm

import "testing"

func TestCrossLinuxRuntimeMatrixX86InsertExtractMaskedNativeMemory(t *testing.T) {
	x86InsertExtractMaskedMemoryRuntime(t)
}
