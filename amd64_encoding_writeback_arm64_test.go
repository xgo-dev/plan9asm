package plan9asm

import "testing"

// These source instructions use their actual portable ARM64 backend paths.
// Native x86-only reciprocal/ER and MXCSR-reading paths remain in the object
// inventory; no intrinsic or status computation is stripped for this host.
func TestX86EncodingWritebackPortableARM64(t *testing.T) {
	x86EncodingWritebackRuntime(t, x86ScalarCountHostExecution(t), "portable")
}
