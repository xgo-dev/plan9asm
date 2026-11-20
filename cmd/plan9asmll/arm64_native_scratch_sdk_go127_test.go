//go:build go1.27

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestCompileOneARM64NativeScratchActualSDKWrapperAndBody(t *testing.T) {
	// This is first-party original source. The SDK dependency is selected by
	// stock Go, including its real declaration, ABI wrapper and assembly body;
	// an empty/default external FuncSig cannot describe this three-word call.
	source := arm64NativeScratchClosureSource(`TEXT ·Value(SB),NOSPLIT,$40-16
    MOVD $0,R1
    MOVD R1,8(RSP)
    MOVD R1,16(RSP)
    MOVD R1,24(RSP)
    CALL runtime·memmove(SB)
    MOVD $11,R1
    MOVD R1,ret+8(FP)
    RET
`)
	pkg, input, config := arm64NativeScratchClosureFixture(t, source,
		"import _ \"runtime\"\nfunc Value(n uint64) uint64\n")
	output := filepath.Join(t.TempDir(), "sdk.ll")
	if err := compileOne(pkg, plan9asm.ArchARM64, "linux", "arm64", "aarch64-unknown-linux-gnu",
		asmTask{PkgPath: pkg.PkgPath, AsmFile: input, OutLL: output}, false, config); err != nil {
		t.Fatalf("actual whole SDK body must define its scratch before any read and retain its real ABI0 wrapper tuple: %v", err)
	}
	object := strings.TrimSuffix(output, ".ll") + ".o"
	if info, err := os.Lstat(object); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		t.Fatalf("actual SDK source closure produced no eligible LLVM object: %v", err)
	}
}
