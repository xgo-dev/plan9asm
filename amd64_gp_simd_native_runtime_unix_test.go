//go:build unix

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86GPSIMDNativeResultsAndFaults(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var source, declarations, prototypes, originals, rows strings.Builder
	count := 0
	for _, row := range x86GPSIMDNativeOracle {
		for discarded := 0; discarded < 2; discarded++ {
			name, original := fmt.Sprintf("F%d", count), fmt.Sprintf("Original%d", count)
			body := row.op + " -1(DX)(BX*1),X0\nPEXTRQ $0,X0,AX\n"
			native := row.original + " (DI),X0\nMOVQ X0,AX\n"
			if discarded == 1 {
				body += "MOVQ $0x87654321fedcba98,AX\n"
				native += "MOVQ $0x87654321fedcba98,AX\n"
			}
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-16\nMOVQ p+0(FP),DX\nMOVL $1,BX\n%sMOVQ AX,ret+8(FP)\nRET\n", name, body)
			fmt.Fprintf(&declarations, "func %s(p *[8]byte) uint64\n", name)
			code := x86OrderingHintGoBytes(t, "amd64", "TEXT native(SB),4,$0-0\n"+native+"RET\n")
			var bytes []string
			for _, b := range code {
				bytes = append(bytes, fmt.Sprintf("0x%02x", b))
			}
			symbol := original
			if strings.Contains(execution.triple, "apple") {
				symbol = "_" + symbol
			}
			fmt.Fprintf(&originals, "__asm__(%q);\n", ".text\n.globl "+symbol+"\n"+symbol+":\n.byte "+strings.Join(bytes, ",")+"\n")
			fmt.Fprintf(&prototypes, "extern uint64_t %s(const uint8_t*);\nextern uint64_t %s(const uint8_t*);\n", name, original)
			fmt.Fprintf(&rows, "{%s,%s,%d,%d},\n", name, original, row.width, discarded)
			count++
		}
	}
	if count != 10 {
		t.Fatal("incomplete live/dead GP/X family", count)
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	driver := fmt.Sprintf(x86NativeScalarReadRuntimeC, prototypes.String(), originals.String(), rows.String())
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, optimized := range []bool{false, true} {
				t.Run(fmt.Sprintf("O2=%t", optimized), func(t *testing.T) {
					text, level := ir, "-O0"
					if optimized {
						text, level = x86MulDivRoundOptimize(t, ir), "-O2"
					}
					output := execution.compileAndRunLLVM(t, "gp-x-native", text, driver, level)
					if string(output) != "10 native scalar kernels: numerical 1280, faults 120, tripwires 2; failures 0\n" {
						t.Fatal("original/LLVM GP/X numerical/zero bytes or read widths differ:", string(output))
					}
					t.Log(strings.TrimSpace(string(output)))
				})
			}
		})
	}
}
