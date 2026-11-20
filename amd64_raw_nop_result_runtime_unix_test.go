//go:build unix

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86RawNOPPairedNativeRead(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	literal := x86RawDisplacementDirectives([]byte{0x66, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0})
	var source, declarations, prototypes, originals, rows strings.Builder
	count := 0
	for _, vector := range []bool{false, true} {
		for _, dead := range []bool{false, true} {
			name, original := fmt.Sprintf("F%d", count), fmt.Sprintf("Original%d", count)
			read, width, inputByte, outputByte := "MOVQ (DX),AX\n", 8, 0, 0
			if vector {
				read, width, inputByte, outputByte = "MOVOU (DX),X1\nMOVQ X1,AX\n", 16, 1, 1
			}
			body := literal + read + literal
			discarded := 0
			if dead {
				body += "MOVQ $0x87654321fedcba98,AX\n"
				discarded = 1
			}
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-16\nMOVQ p+0(FP),DX\n%sMOVQ AX,ret+8(FP)\nRET\n", name, body)
			fmt.Fprintf(&declarations, "func %s(p *[64]byte) uint64\n", name)
			code := x86OrderingHintGoBytes(t, "amd64", "TEXT native(SB),4,$0-0\n"+strings.ReplaceAll(body, "(DX)", "(DI)")+"RET\n")
			var encoded []string
			for _, b := range code {
				encoded = append(encoded, fmt.Sprintf("0x%02x", b))
			}
			symbol := original
			if strings.Contains(execution.triple, "apple") {
				symbol = "_" + symbol
			}
			fmt.Fprintf(&originals, "__asm__(%q);\n", ".text\n.globl "+symbol+"\n"+symbol+":\n.byte "+strings.Join(encoded, ",")+"\n")
			fmt.Fprintf(&prototypes, "extern uint64_t %s(const uint8_t*);\nextern uint64_t %s(const uint8_t*);\n", name, original)
			fmt.Fprintf(&rows, "{%s,%s,%d,%d,%d,%d},\n", name, original, width, discarded, inputByte, outputByte)
			count++
		}
	}
	if count != 4 {
		t.Fatal("incomplete scalar/vector live/dead matrix", count)
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
					output := execution.compileAndRunLLVM(t, "nop-native-read", text, driver, level)
					if string(output) != "4 native scalar kernels: numerical 512, faults 48, tripwires 2; failures 0\n" {
						t.Fatal("original NOP/read composition differs from LLVM", string(output))
					}
					t.Log(strings.TrimSpace(string(output)))
				})
			}
		})
	}
}
