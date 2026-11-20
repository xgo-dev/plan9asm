//go:build linux && amd64

package plan9asm

import (
	"os/exec"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86RepeatEmptyGuardNativeAMD64(t *testing.T) {
	x87IA32RequireNativeHost(t)
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("native repeated comparison requires LLVM22 llc/clang")
	}
	execution := x86FloatCompareExecution{llc: llc, triple: "x86_64-unknown-linux-gnu",
		compiler: []string{clang, "-target", "x86_64-unknown-linux-gnu"}}
	repeatEmptyExecuteOriginal(t, "amd64", execution)
	repeatEmptyExecuteLLVM(t, "amd64", execution)
	x87IA32RequireNativeHost(t)
}

func TestCrossLinuxRuntimeMatrixX86RepeatEmptyGuardNative386(t *testing.T) {
	x87IA32RequireNativeHost(t)
	llc := findLLVM22Tool("llc")
	compiler, err := exec.LookPath("i686-linux-gnu-gcc")
	if llc == "" || err != nil {
		t.Fatal("native 386 repeated comparison requires LLVM22/i686 compiler", err)
	}
	execution := x86FloatCompareExecution{llc: llc, triple: "i386-unknown-linux-gnu",
		compiler: []string{compiler, "-static", "-no-pie"}}
	repeatEmptyExecuteOriginal(t, "386", execution)
	repeatEmptyExecuteLLVM(t, "386", execution)
	x87IA32RequireNativeHost(t)
}
