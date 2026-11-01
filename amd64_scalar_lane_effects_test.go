package plan9asm

import (
	"fmt"
	"testing"
)

// This is the memHash32AES input/insert/result pattern without borrowing AES
// effects, native pointers or any package-specific permission. The original
// typed ABI0 frame independently supplies both numerical scalar inputs.
func TestX86ScalarLaneInsertResultInitializationFirstParty(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			const source = "TEXT ·view(SB),4,$0-12\nMOVL h+4(FP),X0\nPINSRD $1,k+0(FP),X0\nMOVL X0,ret+8(FP)\nRET\n"
			goAssemblerOracleOutput(t, target.arch, source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func view(k,h uint32) uint32\n", target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatalf("original initialized scalar lane insert did not close its result: %v", err)
					}
					compileLLVMToObject(t, llc, target.triple, "scalar-lane-result-"+api+".ll", "scalar-lane-result-"+api+".o", ir)
				})
			}
		})
	}
}

func TestX86ScalarLaneInsertCompleteNamesRetainTypedResults(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, op := range []string{"PINSRB", "PINSRW", "PINSRD", "PINSRQ", "VPINSRB", "VPINSRW", "VPINSRD", "VPINSRQ"} {
			if target.arch == "386" && (op == "PINSRQ" || op[0] == 'V') {
				continue // Go's complete 386 frontend excludes these named forms.
			}
			t.Run(target.triple+"/"+op, func(t *testing.T) {
				args := "$1,k+0(FP),X0"
				if op[0] == 'V' {
					args += ",X1"
				}
				output := "X0"
				if op[0] == 'V' {
					output = "X1"
				}
				source := fmt.Sprintf("TEXT ·view(SB),4,$0-24\nMOVQ h+8(FP),X0\n%s %s\nMOVQ %s,ret+16(FP)\nRET\n", op, args, output)
				goAssemblerOracleOutput(t, target.arch, source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					if ir, err := x86ScalarFPBitViewAPI(t, source, "func view(k,h uint64) uint64\n", target.arch, target.triple, api); err != nil || ir == "" {
						t.Errorf("%s lost initialized insertion result: %v", api, err)
					}
				}
			})
		}
	}
}
