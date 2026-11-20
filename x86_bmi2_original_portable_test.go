package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86BMI2VariableShiftRepairedOriginalPortableValuesAndFlags(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang required")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	driver := x86X87FunctionLiteral(t, "amd64_lower_bmi2_shift_test.go",
		"TestAMD64BMI2VariableShiftRuntimeSemantics", "mainC")
	for _, raw := range []bool{false, true} {
		source := x86BMI2VariableShiftRepairedRuntimeSource(t)
		if raw {
			lines := strings.Split(source, "\n")
			count := 0
			for index, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "SHLX") || strings.HasPrefix(line, "SHRX") || strings.HasPrefix(line, "SARX") {
					lines[index] = x86RawNumericalInstruction(t, "amd64", line)
					count++
				}
			}
			if count != 5 {
				t.Fatal("original BMI2 numerical source directory changed", count)
			}
			source = strings.Join(lines, "\n")
		}
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(fmt.Sprintf("raw=%t/%s", raw, api), func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source, "func bmi2shiftsemantics(out *[48]byte)", "amd64", triple, api)
				if err != nil {
					t.Fatal("Go-valid original BMI2 fixture rejected", err)
				}
				for index, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						compileAndRunRuntimeTestForTarget(t, llc, clang,
							fmt.Sprintf("bmi2-original-%t-%s-%d-%s", raw, api, index, level[1:]), triple, text, driver, nil)
					}
				}
			})
		}
	}
	t.Log("original portable numerical and FLAGS oracle, not original native BMI opcode execution")
}
