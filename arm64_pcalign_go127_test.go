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

func TestARM64RawPCAlignmentMaxBindsGoObjectTarget(t *testing.T) {
	for _, test := range []struct {
		directive string
		target    int64
	}{
		{"PCALIGNMAX $32,$11", 20},
		{"PCALIGNMAX $32,$12", 32},
		{"PCALIGNMAX $32,$13", 32},
	} {
		t.Run(test.directive, func(t *testing.T) {
			checkARM64RawPCAlignment(t, test.directive, test.target)
		})
	}
}
