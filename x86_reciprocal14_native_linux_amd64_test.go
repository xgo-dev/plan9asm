//go:build linux && amd64 && plan9asm_native_avx512

package plan9asm

import "testing"

// Explicit qualification only: default CI does not discover these owners.
// Supplying the tag requires real hardware and never turns missing ISA into PASS.
func TestX86Reciprocal14NativeFAMD64(t *testing.T) {
	x87IA32RequireNativeHost(t)
	x86RunReciprocal14Native(t, 5)
	x87IA32RequireNativeHost(t)
}

func TestX86Reciprocal14NativeVLAMD64(t *testing.T) {
	x87IA32RequireNativeHost(t)
	x86RunReciprocal14Native(t, 6)
	x87IA32RequireNativeHost(t)
}
