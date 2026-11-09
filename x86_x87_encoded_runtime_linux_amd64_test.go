package plan9asm

import "testing"

func TestCrossLinuxRuntimeMatrixX87EncodedTenByteOriginal(t *testing.T) {
	x87IA32RequireNativeHost(t)
	x87EncodedRuntime(t, true)
}
