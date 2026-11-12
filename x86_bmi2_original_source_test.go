package plan9asm

import (
	"strings"
	"testing"
)

func TestX86BMI2VariableShiftOriginalImmediateIsGoRejected(t *testing.T) {
	source := x86X87FunctionLiteral(t, "amd64_lower_bmi2_shift_test.go",
		"TestAMD64BMI2VariableShiftRuntimeSemantics", "source")
	goAssemblerOracleOutput(t, "amd64", "#include \"textflag.h\"\n"+source, "", false)
}

func x86BMI2VariableShiftRepairedRuntimeSource(t *testing.T) string {
	t.Helper()
	source := x86X87FunctionLiteral(t, "amd64_lower_bmi2_shift_test.go",
		"TestAMD64BMI2VariableShiftRuntimeSemantics", "source")
	const invalid = "MOVQ $-81985529216486896, 8(DI)"
	if strings.Count(source, invalid) != 1 {
		t.Fatal("original BMI2 fixture lost its identified invalid imm64 store")
	}
	return strings.Replace(source, invalid, "MOVQ $-81985529216486896, R9\n\tMOVQ R9, 8(DI)", 1)
}

func TestX86BMI2VariableShiftRepairedOriginalSourceObjects(t *testing.T) {
	for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86RawNumericalFamilyObjects(t, x86BMI2VariableShiftRepairedRuntimeSource(t),
				"func bmi2shiftsemantics(out *[48]byte)", "amd64", triple)
		})
	}
}
