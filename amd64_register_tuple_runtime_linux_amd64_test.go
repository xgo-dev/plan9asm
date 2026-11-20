//go:build linux && amd64 && go1.27

package plan9asm

import (
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixAMD64RegisterTupleSDKKernel(t *testing.T) {
	TestAMD64RegisterTupleResultSDKOriginalGoObject(t)
	execution := x86FloatCompareExecutionTools(t)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir := amd64RegisterTupleSDKIR(t, api)
			for _, optimized := range []bool{false, true} {
				body, label := ir, "IR-O0"
				if optimized {
					body, label = x86MulDivRoundOptimize(t, ir), "IR-O2"
				}
				for _, level := range []string{"-O0", "-O2"} {
					t.Run(label+"/backend"+level, func(t *testing.T) {
						output := execution.compileAndRunLLVM(t, "sdk-register-tuple", body, amd64RegisterTupleKernelOracle, level)
						const expected = "SDK_REGISTER_TUPLE_KERNEL_PASS cases=64 fields=192"
						if strings.TrimSpace(string(output)) != expected {
							t.Fatalf("independent kernel/errno/tuple/canary oracle: %q", output)
						}
						t.Log("64 calls and 192 independently expected scalar fields; C uses only a void/pointer output shim")
					})
				}
			}
		})
	}
}
