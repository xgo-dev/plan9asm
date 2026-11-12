//go:build go1.27 && darwin && (amd64 || arm64)

package plan9asm

import (
	"runtime"
	"testing"
)

func TestGoX86NumericalSBReadMutableHostDiagnostic(t *testing.T) {
	if runtime.GOARCH == "arm64" && !rosettaAvailable() {
		t.Fatal("required AMD64 host diagnostic needs Rosetta")
	}
	execution := x86FloatCompareExecutionTools(t)
	t.Log("retargeted host numerical/volatile/canary/fault diagnostic, not Linux native Go ABI execution")
	numericalRuntimeExecute(t, "amd64", execution, false)
}

func TestGoX86NumericalSBReadMutableLocalHostDiagnostic(t *testing.T) {
	if runtime.GOARCH == "arm64" && !rosettaAvailable() {
		t.Fatal("required AMD64 local host diagnostic needs Rosetta")
	}
	t.Log("retargeted composed local numerical/canary/fault diagnostic, not Linux native Go ABI execution")
	numericalLocalMutableRuntime(t, x86FloatCompareExecutionTools(t), false)
}
