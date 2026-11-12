//go:build unix && go1.27

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Each backend checks FLAGS against its own actual global addresses. Different
// linkers need not place the two objects in the same relative order. Address
// excursions are integer operations and are never dereferenced here.
func fixedLocalAddressFlagsProgram(triple string) (assembly, declarations, original, driver string) {
	operations := []string{
		"ADDQ CX,SI\nSETCS DL",
		"SUBQ CX,SI\nSETCS DL",
		"ADDQ CX,SI\nINCQ SI\nSETEQ DL",
		"ADDQ CX,SI\nDECQ SI\nSETEQ DL",
		"ADDQ CX,SI\nMOVQ $·Other(SB),DI\nCMPQ SI,DI\nSETCS DL",
	}
	declarations = "var Table, Other [4]uint64\n"
	var goFunctions, cFunctions, cDeclarations strings.Builder
	prefix := ""
	if strings.Contains(triple, "apple") {
		prefix = "_"
	}
	for index, operation := range operations {
		name := fmt.Sprintf("Flags%d", index)
		assembly += fixedLocalDataAddressFunction(name, "MOVQ $·Table(SB),SI\n"+operation)
		declarations += "func " + name + "(a uint64) uint64\n"
		fmt.Fprintf(&goFunctions, "%s,", name)
		fmt.Fprintf(&cFunctions, "flags%d,", index)
		fmt.Fprintf(&cDeclarations, "extern uint64_t flags%d(uint64_t) __asm__(%s);\n", index,
			runtimeCAsmLabel(prefix+"example.invalid/framefixture."+name))
	}
	original = `package main
import ("fmt"; "unsafe")
` + declarations + `
func expected(index int, base, other, delta uint64) uint64 {
    var flag bool
    switch index {
    case 0: flag = base+delta < base
    case 1: flag = base < delta
    case 2: flag = base+delta+1 == 0
    case 3: flag = base+delta-1 == 0
    case 4: flag = base+delta < other
    default: panic("unknown reference operation")
    }
    if flag {
        return 1
    }
    return 0
}
func main() {
    base := uint64(uintptr(unsafe.Pointer(&Table[0])))
    other := uint64(uintptr(unsafe.Pointer(&Other[0])))
    inputs := []uint64{0,1,8,^uint64(0),-base,-base-1,1-base,other-base-1,other-base,other-base+1}
    for i := range Table {
        Table[i] = uint64(i+1)*0x0102030405060708
        Other[i] = ^Table[i]
    }
    before, beforeOther := Table, Other
    functions := []func(uint64)uint64{` + goFunctions.String() + `}
    for index, function := range functions {
        for sample, delta := range inputs {
            want, got := expected(index,base,other,delta), function(delta)
            if got != want || Table != before || Other != beforeOther {
                panic(fmt.Sprintf("case=%d sample=%d got=%d want=%d",index,sample,got,want))
            }
            fmt.Printf("%d %d PASS\n",index,sample)
        }
    }
}
`
	driver = "#include <stdint.h>\n#include <stdio.h>\n" + runtimeCAsmLabelPreamble + cDeclarations.String() +
		fmt.Sprintf("uint64_t table[4] __asm__(%s);\nuint64_t other_table[4] __asm__(%s);\n",
			runtimeCAsmLabel(prefix+"example.invalid/framefixture.Table"),
			runtimeCAsmLabel(prefix+"example.invalid/framefixture.Other")) + `
static uint64_t expected(unsigned index, uint64_t base, uint64_t other, uint64_t delta) {
    switch (index) {
    case 0: return base+delta < base;
    case 1: return base < delta;
    case 2: return base+delta+1 == 0;
    case 3: return base+delta-1 == 0;
    case 4: return base+delta < other;
    default: return UINT64_MAX;
    }
}
int main(void) {
    uint64_t base=(uintptr_t)table, other=(uintptr_t)other_table;
    uint64_t inputs[]={0,1,8,UINT64_MAX,-base,-base-1,1-base,other-base-1,other-base,other-base+1};
    uint64_t (*functions[])(uint64_t)={` + cFunctions.String() + `};
    for (unsigned i=0;i<4;i++) {
        table[i]=(uint64_t)(i+1)*UINT64_C(0x0102030405060708);
        other_table[i]=~table[i];
    }
    for (unsigned index=0;index<5;index++) {
        for (unsigned sample=0;sample<10;sample++) {
            uint64_t want=expected(index,base,other,inputs[sample]);
            uint64_t got=functions[index](inputs[sample]);
            if (got!=want) {
                fprintf(stderr,"case=%u sample=%u got=%llu want=%llu\n",
                    index,sample,(unsigned long long)got,(unsigned long long)want);
                return 1;
            }
            for (unsigned i=0;i<4;i++) {
                uint64_t value=(uint64_t)(i+1)*UINT64_C(0x0102030405060708);
                if (table[i]!=value || other_table[i]!=~value) {
                    return 2;
                }
            }
            printf("%u %u PASS\n",index,sample);
        }
    }
    return 0;
}
`
	return
}

func fixedLocalAddressFlagsRuntime(t *testing.T, execution x86FloatCompareExecution, execute bool) {
	t.Helper()
	goAMD64FramePrepareOwnedToolCache(t)
	assembly, declarations, original, driver := fixedLocalAddressFlagsProgram(execution.triple)
	var want []string
	for index := 0; index < 5; index++ {
		for sample := 0; sample < 10; sample++ {
			want = append(want, fmt.Sprintf("%d %d PASS", index, sample))
		}
	}
	check := func(output []byte) {
		t.Helper()
		if strings.TrimSpace(string(output)) != strings.Join(want, "\n") {
			t.Fatalf("native address FLAGS reference did not complete every case:\n%s", output)
		}
	}
	if execute {
		check(x86ScalarFloatIntegerOriginalOutput(t, execution, assembly, original))
	} else {
		x86COMICompileOriginalGo(t, map[string]string{
			"go.mod": "module addressflags\ngo 1.20\n", "main.go": original, "original_amd64.s": assembly,
		}, false)
	}
	pkg, request, file, options := fixedLocalTransportFixture(t, assembly, declarations,
		runtime.GOOS+"/amd64", execution.triple)
	fixedLocalResultsRuntimeAPIs(t, pkg, request, file, options, assembly,
		func(t *testing.T, ir string, err error) {
			if err != nil {
				t.Fatal(err)
			}
			for _, level := range []string{"-O0", "-O2"} {
				t.Run(level, func(t *testing.T) {
					input := ir
					if level == "-O2" {
						input = x86MulDivRoundOptimize(t, ir)
					}
					if execute {
						check(execution.compileAndRunLLVM(t, "address-flags", input, driver, level))
					} else {
						execution.compileLLVM(t, "address-flags", input, driver, level)
					}
				})
			}
		})
	t.Logf("5 complete functions, 10 deltas from each backend's own addresses, independent arithmetic references and 64-byte global canaries; execute=%v", execute)
}

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalAddressFlags(t *testing.T) {
	execution := x86FloatCompareRuntimeTools(t, x86FloatCompareSSE)
	t.Run("address-flags", func(t *testing.T) {
		fixedLocalAddressFlagsRuntime(t, execution, true)
	})
	t.Run("machine-bits", func(t *testing.T) {
		fixedLocalMachineBitsRuntime(t, execution, true)
	})
	for _, scope := range []string{"auxiliary", "vector spill", "multiply"} {
		t.Run(scope, func(t *testing.T) {
			fixedLocalMachineRuntime(t, execution, true, scope)
		})
	}
}

func TestGoAMD64FixedLocalAddressFlagsRuntimeObjects(t *testing.T) {
	fixedLocalAddressFlagsRuntime(t, fixedLocalPackedCompileOnlyTools(t), false)
}
