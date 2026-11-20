//go:build linux && amd64

package plan9asm

import (
	"os/exec"
	"testing"
)

// Required Linux native owner: both ISA children execute. Other hosts do not
// certify this owner, and missing tools on its actual host are fatal.
func TestCrossLinuxRuntimeMatrixX86ByteSwapOriginalGoAndLLVM(t *testing.T) {
	x87IA32RequireNativeHost(t)
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("native BSWAP owner requires LLVM22 llc/clang")
	}
	compiler386, err := exec.LookPath("i686-linux-gnu-gcc")
	if err != nil {
		t.Fatal("native BSWAP owner requires i686-linux-gnu-gcc", err)
	}
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			execution := x86FloatCompareExecution{llc: llc, triple: "x86_64-unknown-linux-gnu",
				compiler: []string{clang, "-target", "x86_64-unknown-linux-gnu"}}
			if arch == "386" {
				execution.triple = "i386-unknown-linux-gnu"
				execution.compiler = []string{compiler386, "-static", "-no-pie", "-maccumulate-outgoing-args"}
			}
			x86ByteSwapExecuteOriginalAndLLVM(t, arch, execution)
		})
	}
	x87IA32RequireNativeHost(t)
}
