//go:build go1.27

package plan9asm

import "testing"

func TestCrossLinuxRuntimeMatrixX86OwnedPackedArithmetic(t *testing.T) {
	x87IA32RequireNativeHost(t)
	execution := x86FloatCompareExecutionTools(t)
	if len(execution.prefix) != 0 || execution.preserveArgv0 {
		t.Fatal("owned arithmetic differential execution requires native AMD64")
	}
	t.Logf("%s", execution.run(t, ownedPackedArithmeticRuntimePreflight(t, execution)))
	assembly, declarations, inputs, expected := ownedPackedArithmeticRuntimeProgram(t)
	fixedLocalResultsRuntime(t, assembly, declarations, inputs, expected)
}
