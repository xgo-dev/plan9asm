//go:build !linux || !amd64

package plan9asm

import "testing"

func x86PackedReductionRequireNativeHost(t *testing.T) {
	t.Helper()
	t.Fatal("required native reduction owners execute only on actual Linux/amd64; other hosts retain their object and portable counterparts")
}
