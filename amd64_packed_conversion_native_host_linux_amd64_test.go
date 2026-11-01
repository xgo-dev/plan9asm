package plan9asm

import "testing"

func x86PackedConversionRequireNativeHost(t *testing.T) {
	t.Helper()
	x87IA32RequireNativeHost(t)
}
