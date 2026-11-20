package plan9asm

import "testing"

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalSHA(t *testing.T) {
	execution := fixedLocalVEXNativeTools(t)
	t.Logf("%s", execution.run(t, fixedLocalSHARuntimePreflight(t, execution)))
	// Original Go independently computes all 128 result bits and legacy
	// upper aliases after every operation, for 16 asymmetric input patterns.
	fixedLocalVectorRuntime(t, execution, true, fixedLocalSHARuntimeKernels(t))
	x87IA32RequireNativeHost(t)
}

func TestCrossLinuxRuntimeMatrixGoAMD64SHAFaults(t *testing.T) {
	execution := fixedLocalVEXNativeTools(t)
	t.Logf("%s", execution.run(t, fixedLocalSHARuntimePreflight(t, execution)))
	fixedLocalSHAFaultRuntime(t, execution, true)
	x87IA32RequireNativeHost(t)
}
