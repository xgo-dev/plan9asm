//go:build unix

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func fixedLocalAffineRuntimeProgram(t *testing.T, triple string) (string, string, string, string) {
	t.Helper()
	bodies := []string{
		"ADDQ AX,SI\nMOVQ (SI),AX",
		"ADDQ SI,AX\nMOVQ (AX),AX",
		"SUBQ AX,SI\nMOVQ (SI),AX",
		"LEAQ -8(SI)(AX*2),CX\nMOVQ (CX),AX",
		"INCQ SI\nDECQ SI\nMOVQ (SI),AX",
		"MOVQ $0,AX\nCMPQ SI,DI\nSETCS AL",
		"MOVQ $0,AX\nMOVQ SI,8(SP)\nCMPQ DI,8(SP)\nSETCS AL",
		"MOVQ $0,AX\nMOVQ SI,8(SP)\nCMPQ 8(SP),DI\nSETCS AL",
		"CMPQ AX,$0\nJEQ left\nLEAQ 8(SI),CX\nJMP join\nleft:\nLEAQ 16(SI),CX\njoin:\nMOVQ (CX),AX",
		"CMPQ AX,$0\nJEQ join\nMOVQ SI,8(SP)\njoin:",
	}
	for _, register := range []string{"BP", "R14"} {
		bodies = append(bodies,
			fmt.Sprintf("MOVQ SI,%s\nADDQ AX,%s\nMOVQ (%s),AX", register, register, register),
			fmt.Sprintf("LEAQ 8(SI),%s\nADDQ AX,%s\nMOVQ (%s),AX", register, register, register))
	}
	var assembly, declarations, goRows, cRows, cDeclarations strings.Builder
	prefix := ""
	if strings.Contains(triple, "apple") {
		prefix = "_"
	}
	for index, body := range bodies {
		_, _, source := fixedLocalInputFixture(t, body)
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(strings.Replace(source, "·Value", "·"+name, 1))
		fmt.Fprintf(&declarations, "func %s(p, q *uint64, a uint64) uint64\n", name)
		fmt.Fprintf(&goRows, "%s,\n", name)
		fmt.Fprintf(&cRows, "value%d,\n", index)
		fmt.Fprintf(&cDeclarations, "extern uint64_t value%d(uint64_t *, uint64_t *, uint64_t) __asm__(%s);\n",
			index, runtimeCAsmLabel(prefix+"example.invalid/framefixture."+name))
	}
	original := `package main
import "fmt"
` + declarations.String() + `
func main() {
    rows := []func(*uint64, *uint64, uint64) uint64{
` + goRows.String() + `
    }
    var data [16]uint64
    for i := range data { data[i] = uint64(i)*0x0102030405060708 ^ 0xfedcba9876543210 }
    for n, call := range rows {
        for v := 0; v < 4; v++ {
            got := call(&data[8], &data[7+v%3], uint64(v*8))
            fmt.Printf("%d %d %016x\n", n, v, got)
        }
    }
    for i, got := range data {
        if got != uint64(i)*0x0102030405060708 ^ 0xfedcba9876543210 { panic("input modified") }
    }
}
`
	driver := `#include <stdint.h>
#include <stdio.h>
` + runtimeCAsmLabelPreamble + cDeclarations.String() + `
int main(void) {
    uint64_t (*const rows[])(uint64_t *, uint64_t *, uint64_t) = {
` + cRows.String() + `
    };
    uint64_t data[16];
    for (unsigned i = 0; i < 16; i++) data[i] = i*UINT64_C(0x0102030405060708) ^ UINT64_C(0xfedcba9876543210);
    for (unsigned n = 0; n < sizeof(rows)/sizeof(rows[0]); n++) {
        for (unsigned v = 0; v < 4; v++) {
            printf("%u %u %016llx\n", n, v, (unsigned long long)rows[n](&data[8], &data[7+v%3], v*8));
        }
    }
    for (unsigned i = 0; i < 16; i++) {
        if (data[i] != (i*UINT64_C(0x0102030405060708) ^ UINT64_C(0xfedcba9876543210))) return 2;
    }
    return 0;
}
`
	return assembly.String(), declarations.String(), original, driver
}

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalAffine(t *testing.T) {
	execution := x86FloatCompareRuntimeTools(t, x86FloatCompareSSE)
	t.Setenv("GOCACHE", t.TempDir())
	assembly, declarations, original, driver := fixedLocalAffineRuntimeProgram(t, execution.triple)
	want := strings.Split(strings.TrimSpace(string(x86ScalarFloatIntegerOriginalOutput(t, execution, assembly, original))), "\n")
	if len(want) != 14*4 {
		t.Fatalf("original Go produced %d rows, want 14 affine kernels x 4 offsets", len(want))
	}
	pkg, request, _, options := fixedLocalTransportFixture(t, assembly, declarations, runtime.GOOS+"/amd64", execution.triple)
	fixedLocalConversionPrepareToolCache(t, request)
	fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"}, func(t *testing.T, ir string, err error) {
		if err != nil {
			t.Fatal(err)
		}
		for _, level := range []string{"-O0", "-O2"} {
			t.Run(level, func(t *testing.T) {
				input := ir
				if level == "-O2" {
					input = x86MulDivRoundOptimize(t, ir)
				}
				got := strings.Split(strings.TrimSpace(string(execution.compileAndRunLLVM(t, "private-affine", input, driver, level))), "\n")
				if len(got) != len(want) {
					t.Fatalf("LLVM rows = %d, original = %d", len(got), len(want))
				}
				for index := range want {
					if got[index] != want[index] {
						t.Fatalf("affine value/compare row %d: original %s; LLVM %s", index, want[index], got[index])
					}
				}
			})
		}
	})
}

func TestGoAMD64FixedLocalInputAffineMemoryFaults(t *testing.T) {
	cases := []fixedLocalInputFaultCase{
		{"ADDQ $8,SI\nMOVQ -8(SI),CX", 8},
		{"SUBQ $8,SI\nMOVQ 8(SI),CX", 8},
		{"ADDQ SI,AX\nMOVQ (AX),CX", 8},
		{"LEAQ 8(SI)(AX*8),CX\nMOVQ -8(CX),AX", 8},
		{"MOVQ SI,BP\nADDQ AX,BP\nMOVQ (BP),CX", 8},
		{"LEAQ 8(SI),BP\nADDQ AX,BP\nMOVQ -8(BP),CX", 8},
	}
	for _, register := range []string{"BP", "R14"} {
		for index, suffix := range []string{"B", "W", "L", "Q"} {
			for _, operands := range []string{"(%s),CX", "AX,(%s)"} {
				operation := "MOVQ SI," + register + "\nMOV" + suffix + " " + fmt.Sprintf(operands, register)
				cases = append(cases, fixedLocalInputFaultCase{operation, 1 << uint(index)})
			}
		}
	}
	fixedLocalInputMemoryFaults(t, cases)
}
