package plan9asm

import "testing"

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalPackedNativeWideBatch00(t *testing.T) {
	fixedLocalPackedNativeWideBatch(t, 0)
}

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalPackedNativeWideBatch01(t *testing.T) {
	fixedLocalPackedNativeWideBatch(t, 1)
}

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalPackedNativeWideBatch02(t *testing.T) {
	fixedLocalPackedNativeWideBatch(t, 2)
}

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalPackedNativeWideBatch03(t *testing.T) {
	fixedLocalPackedNativeWideBatch(t, 3)
}

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalPackedNativeWideBatch04(t *testing.T) {
	fixedLocalPackedNativeWideBatch(t, 4)
}

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalPackedNativeWideBatch05(t *testing.T) {
	fixedLocalPackedNativeWideBatch(t, 5)
}

func fixedLocalPackedNativeWideBatch(t *testing.T, batch int) {
	t.Helper()
	execution := x86PackedDoubleDwordNativeTools(t)
	fixedLocalPackedRuntimeAPIs(t, execution, true, true, []string{"Translate", "Module", "GoModule"}, batch)
}
