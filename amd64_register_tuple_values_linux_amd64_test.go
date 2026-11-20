//go:build linux && amd64

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixAMD64RegisterTupleValues(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	for _, test := range amd64RegisterTupleRuntimeCases() {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(test.name+"/"+api, func(t *testing.T) {
				ir, main := amd64RegisterTupleRuntimeInputs(t, test, api)
				for _, optimized := range []bool{false, true} {
					body, label := ir, "IR-O0"
					if optimized {
						body, label = x86MulDivRoundOptimize(t, ir), "IR-O2"
					}
					for _, level := range []string{"-O0", "-O2"} {
						t.Run(label+"/backend"+level, func(t *testing.T) {
							output := execution.compileAndRunLLVM(t, "register-tuple-values", body, main, level)
							expected := fmt.Sprintf("REGISTER_TUPLE_TRANSLATED_PASS fields=%d calls=32", len(test.results))
							if strings.TrimSpace(string(output)) != expected {
								t.Fatalf("independent tuple values/truncation/canaries: %q", output)
							}
						})
					}
				}
			})
		}
	}
}
