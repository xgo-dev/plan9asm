//go:build go1.27

package plan9asm

import "testing"

// The discovering current-Go source combines PCALIGN with literal NOP padding.
// Go 1.20 rejects PCALIGN; the untagged root still checks every literal NOP and
// paired native-read contract on both the historical and current SDKs.
func TestX86RawNOPResultReadWithCurrentGoAlignment(t *testing.T) {
	x86RawNOPResultReadComposition(t, true)
}
