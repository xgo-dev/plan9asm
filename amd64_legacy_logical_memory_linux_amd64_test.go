package plan9asm

import "testing"

// Required by the cross-runtime CI prefix. The native Linux axis additionally
// checks the original aligned-m128 contract, which Rosetta does not reproduce.
func TestCrossLinuxRuntimeMatrixX86LegacyLogicalMemoryNativeFaults(t *testing.T) {
	x86LegacyLogicalMemoryRuntime(t, true)
}
