package plan9asm

import "testing"

// This counterpart observes the actual Y bank and requires native AVX2.
// It does not substitute a Y observation for AVX512's complete Z bank.
func TestCrossLinuxRuntimeMatrixX86EncodingWritebackAVX2(t *testing.T) {
	x86EncodingWritebackRuntime(t, fixedLocalVEXNativeTools(t), "avx2")
}
