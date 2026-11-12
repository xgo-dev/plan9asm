//go:build linux && amd64

package plan9asm

import "testing"

func TestCrossLinuxRuntimeMatrixX86PackedStringOriginalNativeMemoryFaults(t *testing.T) {
	x87IA32RequireNativeHost(t)
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("native packed-string fault owner requires LLVM22 llc/clang")
	}
	execution := x86FloatCompareExecution{llc: llc, triple: "x86_64-unknown-linux-gnu",
		compiler: []string{clang, "-target", "x86_64-unknown-linux-gnu", "-mno-red-zone"}}
	x86PackedStringRunMemoryFaults(t, execution, true)
	x87IA32RequireNativeHost(t)
}
