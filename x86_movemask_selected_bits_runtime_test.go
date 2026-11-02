package plan9asm

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestX86MoveMaskSelectedBitsPortableValues(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang required")
	}
	arch := "amd64"
	if strconv.IntSize == 32 {
		arch = "386"
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	_, _, layout, _ := x86ResultInitializationFixture(t, arch, "func Value(value uint32) uint32", "RET")
	resultOffset := layout.Frame.Results[0].Offset
	const driver = `#include <stdint.h>
#include <stdio.h>
extern uint32_t MaskAND(uint32_t);
extern uint32_t MaskTEST(uint32_t);
int main(void) {
    for (uint32_t input = 0; input < 256; ++input) {
        const uint32_t expected = input >= 128 ? 1 : 0;
        const uint32_t and_value = MaskAND(input);
        const uint32_t test_value = MaskTEST(input);
        if (and_value != expected || test_value != expected) {
            fprintf(stderr, "input=%u and=%u test=%u expected=%u\n",
                    input, and_value, test_value, expected);
            return 1;
        }
    }
    return 0;
}
`
	// Separate modules keep one form's target-specific backend rejection from
	// hiding other forms' portable results. This owner requires actual host
	// execution and never substitutes native x86, an emulator or a passing skip.
	for _, row := range x86SelectedMoveMaskRows {
		t.Run(row.op+row.bank, func(t *testing.T) {
			var assembly, declarations strings.Builder
			for _, observation := range []struct{ name, body string }{
				{"MaskAND", "ANDL $1,AX\n"},
				{"MaskTEST", "TESTL $1,AX\nSETNE AL\nMOVBLZX AL,AX\n"},
			} {
				// Only this lane's sign byte is source-defined. Every other
				// vector byte deliberately lacks a NUM initialization fact.
				fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-%d\nMOVL value+0(FP),BX\nPINSRB $%d,BX,X0\n%s %s0,AX\n%sMOVL AX,ret+%d(FP)\nRET\n",
					observation.name, resultOffset+4, row.laneBytes-1, row.op, row.bank, observation.body, resultOffset)
				fmt.Fprintf(&declarations, "func %s(value uint32) uint32\n", observation.name)
			}
			goAssemblerOracleOutput(t, arch, assembly.String(), "", true)
			zero := "PXOR X0,X0\n"
			if row.bank == "Y" {
				zero = "VPXOR Y0,Y0,Y0\n"
			}
			complete := strings.ReplaceAll(assembly.String(), "MOVL value+0(FP),BX", zero+"MOVL value+0(FP),BX")
			goAssemblerOracleOutput(t, arch, complete, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run("complete-input/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, complete, declarations.String(), arch, triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete input isolates the existing backend route", err)
					}
				})
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, assembly.String(), declarations.String(), arch, triple, api)
					if err != nil || ir == "" {
						t.Fatal("selected-bit source did not produce portable IR", err)
					}
					for _, optimized := range []bool{false, true} {
						t.Run(fmt.Sprintf("IR-O2=%t", optimized), func(t *testing.T) {
							text := ir
							if optimized {
								text = x86DwordProductIROptimize(t, ir)
							}
							for _, level := range []int{0, 2} {
								t.Run(fmt.Sprintf("backend-O%d", level), func(t *testing.T) {
									compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "movemask-selected-bits", triple, text, driver, nil, level)
								})
							}
						})
					}
				})
			}
		})
	}
}
