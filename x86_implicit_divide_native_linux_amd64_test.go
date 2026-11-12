package plan9asm

import (
	"os/exec"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86ImplicitDivideOriginalGoAndNativeAMD64(t *testing.T) {
	x87IA32RequireNativeHost(t)
	x86RunImplicitDivideNative(t, x86FloatCompareExecutionTools(t), "amd64")
	x87IA32RequireNativeHost(t)
}

func TestCrossLinuxRuntimeMatrixX86ImplicitDivideOriginalGoAndNative386(t *testing.T) {
	x86RunImplicitDivideNative386(t, false)
}

func TestCrossLinuxRuntimeMatrixX86ImplicitDivideLogicalFPOriginalGoAndNativeAMD64(t *testing.T) {
	x87IA32RequireNativeHost(t)
	x86RunImplicitDivideNativeRows(t, x86FloatCompareExecutionTools(t), "amd64", x86DivideLogicalFPNativeRows("amd64"))
	x87IA32RequireNativeHost(t)
}

func TestCrossLinuxRuntimeMatrixX86ImplicitDivideLogicalFPOriginalGoAndNative386(t *testing.T) {
	x86RunImplicitDivideNative386(t, true)
}

func x86RunImplicitDivideNative386(t *testing.T, logicalFP bool) {
	t.Helper()
	x87IA32RequireNativeHost(t)
	llc := findLLVM22Tool("llc")
	compiler, err := exec.LookPath("i686-linux-gnu-gcc")
	if llc == "" || err != nil {
		t.Fatalf("required native mode32 division counterpart tools: LLVM22=%q compiler=%v", llc, err)
	}
	execution := x86FloatCompareExecution{llc: llc, triple: "i386-unknown-linux-gnu",
		compiler: []string{compiler, "-static", "-no-pie"}}
	rows := x86DivideNativeRows("386")
	if logicalFP {
		rows = x86DivideLogicalFPNativeRows("386")
	}
	x86RunImplicitDivideNativeRows(t, execution, "386", rows)
	x87IA32RequireNativeHost(t)
}
