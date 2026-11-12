package plan9asm

import (
	"os/exec"
	"testing"
)

// The actual IA32 oracle uses the Linux amd64 kernel's direct 32-bit execution
// route, whose host checks are deliberately not compiled on other platforms.
func TestCrossLinuxRuntimeMatrixGoModuleOrdinaryGlobalArithmetic386(t *testing.T) {
	x87IA32RequireNativeHost(t)
	llc := findLLVM22Tool("llc")
	compiler, err := exec.LookPath("i686-linux-gnu-gcc")
	if llc == "" || err != nil {
		t.Fatal("LLVM22 and actual IA32 compiler required", err)
	}
	ordinaryGlobalArithmeticRuntime(t, "386", x86FloatCompareExecution{
		llc: llc, triple: "i386-unknown-linux-gnu", compiler: []string{compiler, "-static", "-no-pie"},
	}, true)
}
