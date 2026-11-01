//go:build linux && amd64

package plan9asm

import (
	"os/exec"
	"testing"
)

// These are required actual native Linux counterparts. Neither Rosetta nor a
// QEMU/binfmt route is allowed to count as execution of these owners.
func TestCrossLinuxRuntimeMatrixX86GPSIMDSparseNativeAMD64OriginalGoAndLLVM(t *testing.T) {
	x87IA32RequireNativeHost(t)
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("native sparse-byte owner requires LLVM22 llc/clang")
	}
	execution := x86FloatCompareExecution{llc: llc, triple: "x86_64-unknown-linux-gnu",
		compiler: []string{clang, "-target", "x86_64-unknown-linux-gnu"}}
	x86GPSIMDSparseExecuteOriginalAndLLVM(t, "amd64", execution)
	x87IA32RequireNativeHost(t)
}

func TestCrossLinuxRuntimeMatrixX86GPSIMDSparseNative386OriginalGoAndLLVM(t *testing.T) {
	x87IA32RequireNativeHost(t)
	llc := findLLVM22Tool("llc")
	compiler, err := exec.LookPath("i686-linux-gnu-gcc")
	if llc == "" || err != nil {
		t.Fatal("native 386 sparse-byte owner requires LLVM22/i686 compiler", err)
	}
	execution := x86FloatCompareExecution{llc: llc, triple: "i386-unknown-linux-gnu",
		compiler: []string{compiler, "-static", "-no-pie"}}
	x86GPSIMDSparseExecuteOriginalAndLLVM(t, "386", execution)
	x87IA32RequireNativeHost(t)
}
