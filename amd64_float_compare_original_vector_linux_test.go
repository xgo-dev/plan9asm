//go:build linux && (amd64 || arm64)

package plan9asm

import "testing"

// The Darwin/arm64 Rosetta preflight has AVX=0. This required Linux axis runs
// original AVX machine code, not the translator's former software emulation.
// Missing tools or a guest without AVX fail in the fixture, never skip.
func TestCrossLinuxRuntimeMatrixX86FloatingCompareOriginalVectorPredicates(t *testing.T) {
	x86FloatCompareOriginalVectorRuntime(t)
}
