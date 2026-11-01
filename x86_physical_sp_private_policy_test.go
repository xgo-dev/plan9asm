package plan9asm

import (
	"go/parser"
	"go/token"
	"testing"
)

// Parse the required IA32 counterpart even on ARM64 development hosts. Its
// host receipts, actual static ELF and owned commands cannot become a skip,
// object-only result or an implicit QEMU/Rosetta/native Go entry assertion.
func TestX86LeavePrivateWidthCounterpartRetainsOwnedExecution(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "x86_leave_private_math_linux_amd64_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	required := map[string]int{
		"x87IA32RequireNativeHost": 2, "findLLVM22Tool": 1, "x86FloatCompareExecutionTools": 1,
		"x86LeavePrivateWidthProgram": 1, "x86LEAActualTargetGoObject": 1, "x86PhysicalSPPrivateEmitter": 1,
		"x86DwordProductIROptimize": 1, "x86LeavePrivateWidthC": 1, "execution.compileLLVM": 1,
		"x86NativeOracleIA32Executable": 1, "x87IA32RunDirect": 1, "execution.run": 1,
	}
	const root = "TestCrossLinuxRuntimeMatrixX86LeavePrivateEmitterWidthsAndFlags"
	if err := x86CheckHalfIndirectCommandOwner(file, root, required); err != nil {
		t.Fatal(err)
	}
	for name := range required {
		changed := make(map[string]int)
		for name, count := range required {
			changed[name] = count
		}
		changed[name]++
		if err := x86CheckHalfIndirectCommandOwner(file, root, changed); err == nil {
			t.Fatal("private LEAVE counterpart accepted a missing or duplicate bounded execution edge", name)
		}
	}
}
