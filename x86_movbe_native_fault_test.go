package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86MOVBEDeadAccessPortableFaultBoundaries(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	var source, declarations, prototypes, rows strings.Builder
	count := 0
	for _, op := range []string{"MOVBEW", "MOVBEL", "MOVBEQ"} {
		width := x86MOVBEWidths[Op(op)] / 8
		for _, store := range []bool{false, true} {
			for _, raw := range []bool{false, true} {
				name, line := fmt.Sprint("Dead", count), op+" (AX),BX"
				if store {
					line = op + " BX,(AX)"
				}
				if raw {
					line = x86RawNumericalInstruction(t, "amd64", line)
				}
				fmt.Fprintf(&source, "TEXT %s(SB),4,$0-8\nMOVQ p+0(FP),AX\nMOVL $7,BX\n%s\nMOVL $0,BX\nRET\n", name, line)
				fmt.Fprintf(&declarations, "func %s(p *byte)\n", name)
				fmt.Fprintf(&prototypes, "extern void %s(const uint8_t*);\nstatic int run%s(const uint8_t *p) { %s(p); return 0; }\n", name, name, name)
				fmt.Fprintf(&rows, "{run%s,%d,%d},\n", name, width, width-1)
				count++
			}
		}
	}
	if count != 12 {
		t.Fatal("complete named/raw MOVBE read/write fault directory changed", count)
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	driver := x86MemoryFaultDriver(prototypes.String(), rows.String())
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", execution.triple, api)
			if err != nil {
				t.Fatal("original dead MOVBE access source rejected", err)
			}
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []string{"-O0", "-O2"} {
					executable := execution.compileLLVM(t, "movbe-dead-access", text, driver, level)
					x86CheckMemoryFaultMatrix(t, execution, executable, count)
				}
			}
		})
	}
	t.Log("actual-host translated read/write NULL and page extents, not original native MOVBE execution")
}
