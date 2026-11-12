//go:build linux && amd64

package plan9asm

import (
	"os/exec"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86BitScanNativeAMD64OriginalGoAndLLVM(t *testing.T) {
	x87IA32RequireNativeHost(t)
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("native bit-scan owner requires LLVM22 llc/clang")
	}
	execution := x86FloatCompareExecution{llc: llc, triple: "x86_64-unknown-linux-gnu",
		compiler: []string{clang, "-target", "x86_64-unknown-linux-gnu"}}
	x86BitScanExecuteOriginalAndLLVM(t, "amd64", execution)
	x87IA32RequireNativeHost(t)
}

func TestCrossLinuxRuntimeMatrixX86BitScanNative386OriginalGoAndLLVM(t *testing.T) {
	x87IA32RequireNativeHost(t)
	llc := findLLVM22Tool("llc")
	compiler, err := exec.LookPath("i686-linux-gnu-gcc")
	if llc == "" || err != nil {
		t.Fatal("native i386 bit-scan owner requires LLVM22/i686 compiler", err)
	}
	execution := x86FloatCompareExecution{llc: llc, triple: "i386-unknown-linux-gnu",
		// Keep one fixed outgoing C frame so the SP observation does not
		// mistake GCC's deferred caller-argument cleanup for an unbalanced
		// compiler helper. This changes no translated Go source/ABI role.
		compiler: []string{compiler, "-static", "-no-pie", "-maccumulate-outgoing-args"}}
	x86BitScanExecuteOriginalAndLLVM(t, "386", execution)
	x87IA32RequireNativeHost(t)
}
