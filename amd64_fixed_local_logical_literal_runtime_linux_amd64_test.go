//go:build go1.27

package plan9asm

import "testing"

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalLogicalLiterals(t *testing.T) {
	fixedLocalLogicalLiteralRuntime(t, fixedLocalVEXNativeTools(t), true)
}
