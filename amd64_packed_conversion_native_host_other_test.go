//go:build !linux || !amd64

package plan9asm

import "testing"

func x86PackedConversionRequireNativeHost(t *testing.T) {
	t.Helper()
	t.Fatal("required complete packed conversion runtime needs actual native Linux/amd64")
}
