package plan9asm

import "testing"

func TestCrossLinuxRuntimeMatrixX86IncomingPointerCommutedAdd(t *testing.T) {
	x87IA32RequireNativeHost(t)
	// Reuse the original Go instruction-byte adapter and independent C pointer
	// arithmetic oracle, including wrapped offsets and register/arena canaries.
	x86CallerAddressRuntime(t, []x86CallerAddressRuntimeRow{
		{"ADDQ AX,BX\nMOVQ BX,AX\nTESTQ $-1,AX\nSETMI AX", "a+b", "v", 64, 9},
		{"ADDQ AX,BX\nMOVQ BX,AX\nTESTQ $-1,AX\nSETEQ AX", "a+b", "v", 64, 2},
	})
}
