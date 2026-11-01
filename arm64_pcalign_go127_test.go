//go:build go1.27

package plan9asm

import "testing"

// PCALIGNMAX is newer than the oldest supported Go toolchain. Historical
// lanes still test the translator's complete grammar in the untagged tests.
func TestARM64PCAlignCurrentGoCompleteFormats(t *testing.T) {
	for _, row := range arm64PCAlignTestForms() {
		t.Run(row, func(t *testing.T) {
			requireARM64GoABIInternalObject(t, arm64PCAlignTailSource(row))
		})
	}
}
