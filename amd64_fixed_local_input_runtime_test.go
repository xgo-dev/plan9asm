//go:build unix

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// The independent volatile-byte reference checks an observable access, not
// original SIMD execution or any claimed pointee extent from its Go type.
func TestGoAMD64FixedLocalInputMemoryDeadReadFaults(t *testing.T) {
	fixedLocalInputMemoryFaults(t, []fixedLocalInputFaultCase{{"MOVQ (SI),CX", 8}, {"CMPQ (SI),$0", 8}})
}

func TestGoAMD64FixedLocalInputMemoryDeadMultiplyFaults(t *testing.T) {
	var cases []fixedLocalInputFaultCase
	for index, suffix := range []string{"W", "L", "Q"} {
		for _, instruction := range []string{"IMUL" + suffix + " (SI),AX", "IMUL3" + suffix + " $0,(SI),AX"} {
			cases = append(cases, fixedLocalInputFaultCase{instruction, 2 << uint(index)})
		}
	}
	fixedLocalInputMemoryFaults(t, cases)
}

func TestGoAMD64FixedLocalInputMemoryDeadLogicalFaults(t *testing.T) {
	var cases []fixedLocalInputFaultCase
	for index, suffix := range []string{"B", "W", "L", "Q"} {
		for _, stem := range []string{"AND", "OR", "XOR"} {
			cases = append(cases, fixedLocalInputFaultCase{stem + suffix + " (SI),AX", 1 << uint(index)})
		}
	}
	fixedLocalInputMemoryFaults(t, cases)
}

type fixedLocalInputFaultCase struct {
	instruction string
	width       int
}

func fixedLocalInputMemoryFaults(t *testing.T, cases []fixedLocalInputFaultCase) {
	t.Helper()
	execution := x86ScalarCountHostExecution(t)
	originalTriple := testTargetTriple(runtime.GOOS, "amd64")
	var assembly, declarations, prototypes, rows strings.Builder
	prefix := ""
	if strings.Contains(execution.triple, "apple") {
		prefix = "_"
	}
	for index, row := range cases {
		_, _, source := fixedLocalInputFixture(t, row.instruction+"\nMOVQ $0,AX")
		assembly.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", index), 1))
		fmt.Fprintf(&declarations, "func Value%d(p, q *uint64, a uint64) uint64\n", index)
		fmt.Fprintf(&prototypes, "extern uint64_t value%d(const uint8_t *,uint64_t *,uint64_t) __asm__(%q);\n",
			index, prefix+"example.invalid/framefixture.Value"+fmt.Sprint(index))
		fmt.Fprintf(&prototypes, "static int run%d(const uint8_t *p) {\n    uint64_t output = 0;\n    return value%d(p, &output, 0) != 0;\n}\n", index, index)
		fmt.Fprintf(&rows, "{run%d,%d,%d},\n", index, row.width, row.width-1)
	}
	driver := x86MemoryFaultDriver(prototypes.String(), rows.String())
	pkg, request, _, options := fixedLocalTransportFixture(t, assembly.String(), declarations.String(),
		runtime.GOOS+"/amd64", originalTriple)
	fixedLocalConversionPrepareToolCache(t, request)
	fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
		func(t *testing.T, ir string, err error) {
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(ir, "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "declare ") {
					continue // The common prelude includes unused x86 declarations.
				}
				if strings.Contains(line, " asm ") || strings.Contains(line, "@llvm.x86.") {
					t.Fatal("host scalar oracle cannot execute x86-specific operations")
				}
			}
			for _, pipeline := range []struct{ name, level, ir string }{
				{"backend_O0", "-O0", ir},
				{"IR_O2_backend_O2", "-O2", x86MulDivRoundOptimize(t, ir)},
			} {
				t.Run(pipeline.name, func(t *testing.T) {
					compileLLVMToObject(t, execution.llc, originalTriple, "input-fault.ll", "input-fault.o", pipeline.ir)
					executable := execution.compileLLVM(t, "fixed-local-input-fault", pipeline.ir, driver, pipeline.level)
					x86CheckMemoryFaultMatrix(t, execution, executable, len(cases))
				})
			}
		})
	t.Log("original amd64 three-API objects; actual-host pure scalar LLVM fault execution, not original x86/Go execution")
}
