package plan9asm

import (
	"runtime"
	"testing"
)

// requireX86GoAssemblerResult keeps the Go 1.27 table oracle available to
// tests that must remain visible to llgo. Older compatibility toolchains still
// exercise parsing, translation, and LLVM compilation, but cannot define the
// current operand grammar.
func requireX86GoAssemblerResult(t *testing.T, goarch, src string, wantSuccess bool) {
	t.Helper()
	if !goToolchainAtLeast(runtime.Version(), 1, 27) {
		return
	}
	goAssemblerOracleOutput(t, goarch, src, "", wantSuccess)
}
