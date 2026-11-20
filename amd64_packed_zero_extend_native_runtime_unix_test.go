//go:build unix

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Legacy and VEX-X live/dead kernels use actual original legacy Go bytes as
// their reference. Masked X/Y/Z dead reads use an independent volatile byte
// reference: portable LLVM execution does not certify native AVX512 execution.
// The complete-byte runtime separately checks masks, aliases, FLAGS and MXCSR.
func TestCrossLinuxRuntimeMatrixX86PackedZeroExtendNativeResultsAndFaults(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	const ratiosPerBatch = 3
	for batch := 0; batch < 2; batch++ {
		t.Run(fmt.Sprint("batch", batch), func(t *testing.T) {
			var source, declarations, prototypes, originals, rows strings.Builder
			count := 0
			for _, ratio := range x86ZeroExtendTestRatios[batch*ratiosPerBatch : (batch+1)*ratiosPerBatch] {
				add := func(instruction string, width, discarded int, mask int64, native bool) {
					name := fmt.Sprintf("Widen%d", count)
					original := fmt.Sprintf("Original%d", count)
					count++
					body := "MOVQ p+0(FP),DX\n"
					if strings.Contains(instruction, "K1") {
						body += fmt.Sprintf("MOVQ $%d,AX\nKMOVQ AX,K1\n", mask)
					}
					body += instruction + "\nPEXTRQ $0,X1,AX\n"
					if discarded != 0 {
						body += "MOVQ $0x87654321fedcba98,AX\n"
					}
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-16\n%sMOVQ AX,ret+8(FP)\nRET\n", name, body)
					fmt.Fprintf(&declarations, "func %s(p *[32]byte) uint64\n", name)
					fmt.Fprintf(&prototypes, "extern uint64_t %s(const uint8_t*);\n", name)
					if native {
						nativeBody := "PMOVZX" + ratio.suffix + " (DI),X0\nPEXTRQ $0,X0,AX\n"
						if discarded != 0 {
							nativeBody += "MOVQ $0x87654321fedcba98,AX\n"
						}
						code := x86OrderingHintGoBytes(t, "amd64", "TEXT native(SB),4,$0-0\n"+nativeBody+"RET\n")
						var bytes []string
						for _, value := range code {
							bytes = append(bytes, fmt.Sprintf("0x%02x", value))
						}
						symbol := original
						if strings.Contains(execution.triple, "apple") {
							symbol = "_" + symbol
						}
						fmt.Fprintf(&originals, "__asm__(%q);\n", ".text\n.globl "+symbol+"\n"+symbol+":\n.byte "+strings.Join(bytes, ",")+"\n")
						fmt.Fprintf(&prototypes, "extern uint64_t %s(const uint8_t*);\n", original)
					} else {
						fmt.Fprintf(&originals, "static uint64_t %s(const uint8_t *p) {\n", original)
						fmt.Fprintf(&originals, "    for (unsigned b = 0; b < %d; b++) {\n", width)
						originals.WriteString("        volatile uint8_t value = ((volatile const uint8_t*)p)[b];\n        (void)value;\n    }\n")
						originals.WriteString("    return UINT64_C(0x87654321fedcba98);\n}\n")
					}
					fmt.Fprintf(&rows, "{%s,%s,%d,%d,%d,%d},\n", name, original, width, discarded, ratio.input, ratio.output)
				}
				for _, prefix := range []string{"P", "VP"} {
					for discarded := 0; discarded < 2; discarded++ {
						add(prefix+"MOVZX"+ratio.suffix+" (DX),X1", 16*ratio.input/ratio.output, discarded, 0, true)
					}
				}
				for _, width := range []int{16, 32, 64} {
					bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
					for _, mask := range []int64{0, 1, -1} {
						readWidth := width * ratio.input / ratio.output
						if mask == 0 {
							readWidth = 0
						} else if mask == 1 {
							readWidth = ratio.input
						}
						add("VPMOVZX"+ratio.suffix+".Z (DX),K1,"+bank+"1", readWidth, 1, mask, false)
					}
				}
			}
			if count != 39 || count > 64 {
				t.Fatal("incomplete or oversized widening read matrix", count)
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
						t.Run(fmt.Sprint("O2=", optimized), func(t *testing.T) {
							text, level := ir, "-O0"
							if optimized {
								text, level = x86MulDivRoundOptimize(t, ir), "-O2"
							}
							output := execution.compileAndRunLLVM(t, "widen-native", text, driver, level)
							if string(output) != "39 native scalar kernels: numerical 4992, faults 468, tripwires 2; failures 0\n" {
								t.Fatal("widening numerical/dead/native/masked reads differ:", string(output))
							}
							t.Log("Original legacy Go / portable masked-read reference:", strings.TrimSpace(string(output)))
						})
					}
				})
			}
		})
	}
}
