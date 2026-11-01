//go:build go1.27 && (arm64 || amd64)

package plan9asm

import "testing"

func TestCrossLinuxRuntimeMatrixARM64ByteCarrierNativeResults(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	arm64ByteCarrierRuntimeFamily(t, "linux", triple, llc, compiler, runner)
}
