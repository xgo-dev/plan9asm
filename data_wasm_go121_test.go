//go:build go1.21
// +build go1.21

package plan9asm

import "testing"

func TestWASMDataRelocationWasip1SourceOracle(t *testing.T) {
	wasmDataGoObject(t, wasmDataSource(), "wasip1")
}
