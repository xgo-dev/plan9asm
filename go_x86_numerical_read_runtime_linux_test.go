//go:build go1.27 && linux && (amd64 || arm64)

package plan9asm

import (
	"os/exec"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86NumericalSBReadMutableAMD64(t *testing.T) {
	numericalRuntimeExecute(t, "amd64", x86FloatCompareExecutionTools(t), true)
}

func TestCrossLinuxRuntimeMatrixX86NumericalSBReadMutableLocalAMD64(t *testing.T) {
	numericalLocalMutableRuntime(t, x86FloatCompareExecutionTools(t), true)
}

func TestCrossLinuxRuntimeMatrixX86NumericalSBReadMutable386(t *testing.T) {
	llc := findLLVM22Tool("llc")
	compiler, compilerErr := exec.LookPath("i686-linux-gnu-gcc")
	qemu, qemuErr := exec.LookPath("qemu-i386")
	if llc == "" || compilerErr != nil || qemuErr != nil {
		t.Fatal("LLVM22, i686 Linux compiler and QEMU required", compilerErr, qemuErr)
	}
	execution := x86FloatCompareExecution{llc: llc, triple: "i386-unknown-linux-gnu",
		compiler: []string{compiler, "-no-pie"}, prefix: []string{qemu, "-L", "/usr/i686-linux-gnu"}}
	numericalRuntimeExecute(t, "386", execution, true)
}
