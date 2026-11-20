package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// E4NF source reads remain observable with zero masking and a dead result.
// This exercises portable read extents, not original AVX512 hardware.
func TestX86PermutationShuffleDeadZeroMaskExactTupleFaults(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	var source, declarations, prototypes, callbacks, metadata strings.Builder
	count := 0
	for _, op := range []string{"VPERMD", "VPERMPS", "VSHUFF32X4", "VSHUFF64X2", "VSHUFI32X4", "VSHUFI64X2"} {
		for _, bank := range []string{"Y", "Z"} {
			for _, broadcast := range []bool{false, true} {
				name := fmt.Sprint("PermutationAccess", count)
				width := 32
				if bank == "Z" {
					width = 64
				}
				args, suffix := "(BX),"+bank+"1,K1,"+bank+"2", ".Z"
				if broadcast {
					width, suffix = 4, ".BCST.Z"
					if strings.HasSuffix(op, "64X2") {
						width = 8
					}
				}
				if strings.HasPrefix(op, "VSHUF") {
					args = "$147," + args
				}
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-8\nMOVQ data+0(FP),BX\nVPXORD Z1,Z1,Z1\nMOVL $0,AX\nKMOVD AX,K1\n%s%s %s\nRET\n", name, op, suffix, args)
				fmt.Fprintf(&declarations, "func %s(data *[64]byte)\n", name)
				fmt.Fprintf(&prototypes, "extern void %s(const uint8_t *);\n", name)
				fmt.Fprintf(&callbacks, "static int run%d(const uint8_t *p) { %s(p); return 0; }\n", count, name)
				fmt.Fprintf(&metadata, "{run%d,%d,%d},\n", count, width, width-1)
				count++
			}
		}
	}
	if count != 24 {
		t.Fatal("complete E4NF dead/zero tuple directory changed", count)
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	driver := x86MemoryFaultDriver(prototypes.String()+callbacks.String(), metadata.String())
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", execution.triple, api)
			if err != nil || ir == "" {
				t.Fatal("dead/zero source continuation", err)
			}
			for _, pipeline := range []struct{ name, ir, level string }{
				{"backend_O0", ir, "-O0"}, {"backend_O2", ir, "-O2"},
				{"IR_O2_backend_O2", x86DwordProductIROptimize(t, ir), "-O2"},
			} {
				t.Run(pipeline.name, func(t *testing.T) {
					executable := execution.compileLLVM(t, "permutation-shuffle-access", pipeline.ir, driver, pipeline.level)
					x86CheckMemoryFaultMatrix(t, execution, executable, count)
				})
			}
		})
	}
}
