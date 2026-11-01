//go:build go1.27

package plan9asm

import "testing"

// Mixed DATA uses the existing audited Go 1.27 object producer. Older SDKs
// retain the native-only object gate and an explicit producer rejection test.
func TestGoAMD64FixedLocalPointerChoiceObjects(t *testing.T) {
	rows := fixedLocalPointerChoiceAllPositiveCases()
	if len(rows) != 25 {
		t.Fatal("expected 19 address-choice and 6 complete CFG functions", len(rows))
	}
	assembly, declarations := fixedLocalPointerChoiceProgram(t, fixedLocalChoiceData, rows)
	fixedLocalCompleteVectorObjects(t, assembly, declarations, len(rows))
}
