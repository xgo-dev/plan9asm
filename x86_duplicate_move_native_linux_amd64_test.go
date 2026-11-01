package plan9asm

import (
	"os/exec"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86DuplicateMoveOriginalGoAndNativeAMD64(t *testing.T) {
	x87IA32RequireNativeHost(t)
	execution := x86FloatCompareExecutionTools(t)
	execution.compiler = append(execution.compiler, "-msse3")
	execution.requireAVX(t)
	x86RunDuplicateMoveNative(t, execution, "amd64")
	x87IA32RequireNativeHost(t)
}

func TestCrossLinuxRuntimeMatrixX86DuplicateMoveOriginalGoAndNative386(t *testing.T) {
	x87IA32RequireNativeHost(t)
	llc := findLLVM22Tool("llc")
	compiler, err := exec.LookPath("i686-linux-gnu-gcc")
	if llc == "" || err != nil {
		t.Fatalf("required native mode32 duplicate tools: LLVM22=%q compiler=%v", llc, err)
	}
	execution := x86FloatCompareExecution{llc: llc, triple: "i386-unknown-linux-gnu",
		compiler: []string{compiler, "-static", "-no-pie", "-msse3"}}
	execution.requireAVX(t)
	x86RunDuplicateMoveNative(t, execution, "386")
	x87IA32RequireNativeHost(t)
}
