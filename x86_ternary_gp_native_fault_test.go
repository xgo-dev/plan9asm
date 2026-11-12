package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86TernaryGPDeadReadPortableFaultBoundaries(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	var source, declarations, prototypes, rows strings.Builder
	count := 0
	for _, op := range []string{"ANDNL", "ANDNQ", "PDEPL", "PDEPQ", "PEXTL", "PEXTQ"} {
		bytes, second := 4, "0"
		if strings.HasSuffix(op, "Q") {
			bytes = 8
		}
		if strings.HasPrefix(op, "ANDN") {
			second = "-1" // The numerical ANDN result is zero for every memory value.
		}
		for _, raw := range []bool{false, true} {
			name := fmt.Sprint("Dead", count)
			line := op + " (AX),BX,CX"
			if raw {
				line = x86RawNumericalInstruction(t, "amd64", line)
			}
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-8\nMOVQ source+0(FP),AX\nMOVQ $%s,BX\n%s\nRET\n", name, second, line)
			fmt.Fprintf(&declarations, "func %s(source *byte)\n", name)
			fmt.Fprintf(&prototypes, "extern void %s(const uint8_t*);\nstatic int run%s(const uint8_t *p) { %s(p); return 0; }\n", name, name, name)
			fmt.Fprintf(&rows, "{run%s,%d,%d},\n", name, bytes, bytes-1)
			count++
		}
	}
	if count != 12 {
		t.Fatal("complete named/raw dead-read fault directory changed", count)
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	driver := x86MemoryFaultDriver(prototypes.String(), rows.String())
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", execution.triple, api)
			if err != nil {
				t.Fatal("original dead source rejected", err)
			}
			for _, optimize := range []bool{false, true} {
				text := ir
				if optimize {
					text = x86DwordProductIROptimize(t, ir)
				}
				for _, level := range []string{"-O0", "-O2"} {
					executable := execution.compileLLVM(t, "ternary-dead-read", text, driver, level)
					x86CheckMemoryFaultMatrix(t, execution, executable, count)
				}
			}
		})
	}
	// The reference is a volatile byte access, not the original BMI opcode.
	t.Log("NULL, partial-page and complete-page native extents match portable translated dead reads")
}
