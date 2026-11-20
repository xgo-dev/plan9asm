//go:build go1.27

package plan9asm

import "testing"

func TestGoAMD64FixedLocalNativeAddressObjects(t *testing.T) {
	rows := fixedLocalNativeAddressCases()
	if len(rows) != 17 {
		t.Fatal("complete native-address source inventory changed", len(rows))
	}
	assembly, declarations := fixedLocalPointerChoiceProgram(t, fixedLocalChoiceData, rows)
	fixedLocalCompleteVectorObjects(t, assembly, declarations, len(rows))
}
