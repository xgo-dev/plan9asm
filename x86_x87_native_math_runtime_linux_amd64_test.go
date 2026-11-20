package plan9asm

import "testing"

func TestCrossLinuxRuntimeMatrixX87NativeMathOriginalGoAndLLVM(t *testing.T) {
	x87IA32RequireNativeHost(t)
	x87NativeMathRuntime(t, true)
}
