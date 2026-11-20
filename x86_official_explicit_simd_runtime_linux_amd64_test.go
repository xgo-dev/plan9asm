package plan9asm

import "testing"

func TestCrossLinuxRuntimeMatrixX86OfficialExplicitSIMDOriginalRows(t *testing.T) {
	x87IA32RequireNativeHost(t)
	explicitSIMDRuntime(t, x86FloatCompareExecutionTools(t), true)
}
