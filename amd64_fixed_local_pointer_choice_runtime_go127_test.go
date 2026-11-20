//go:build unix && go1.27

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func fixedLocalPointerChoiceRuntimeProgram(t *testing.T, triple string) (assembly, declarations, original, driver string) {
	t.Helper()
	rows := append(fixedLocalPointerChoiceAllPositiveCases(), fixedLocalNativeAddressCases()...)
	rows = append(rows, fixedLocalMachineAddressCases()...)
	if len(rows) != 48 {
		t.Fatal("complete pointer-choice runtime inventory changed", len(rows))
	}
	assembly, declarations = fixedLocalPointerChoiceProgram(t, fixedLocalChoiceData, rows)
	inputs := []uint64{0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 1 << 63, ^uint64(0)}
	var goInputs, cInputs, goCalls, cCalls, cDeclarations strings.Builder
	for _, value := range inputs {
		fmt.Fprintf(&goInputs, "0x%x,", value)
		fmt.Fprintf(&cInputs, "UINT64_C(0x%x),", value)
	}
	prefix := ""
	if strings.Contains(triple, "apple") {
		prefix = "_"
	}
	for index := range rows {
		label := runtimeCAsmLabel(prefix + fmt.Sprintf("example.invalid/framefixture.Value%d", index))
		fmt.Fprintf(&cDeclarations, "extern uint64_t value%d(uint64_t*,uint64_t*,uint64_t) __asm__(%s);\n", index, label)
		fmt.Fprintf(&goCalls, "check(%d,Value%d)\n", index, index)
		fmt.Fprintf(&cCalls, "check(%d,value%d);\n", index, index)
	}
	original = `package main
import "fmt"
var inputs = []uint64{` + goInputs.String() + `}
func check(index int, fn func(*uint64, *uint64, uint64) uint64) {
    for sample, input := range inputs {
        for alias := 0; alias < 2; alias++ {
            var left, right [32]uint64
            for i := range left {
                left[i] = uint64(i+1)*0x0102030405060708 ^ input
                right[i] = ^left[i] ^ 0x96a5b4c3d2e1f087
            }

            p, q := &left[2], &right[2]
            if alias != 0 {
                q = p
            }
            value := fn(p, q, input)

            fmt.Printf("%d %d %d %016x", index, sample, alias, value)
            for _, buffer := range [2][32]uint64{left, right} {
                for _, value := range buffer {
                    fmt.Printf(" %016x", value)
                }
            }
            fmt.Println()
        }
    }
}
` + declarations + "func main() {\n" + goCalls.String() + "}\n"
	driver = "#include <stdint.h>\n#include <stdio.h>\n" + runtimeCAsmLabelPreamble +
		cDeclarations.String() + "static const uint64_t inputs[]={" + cInputs.String() + `};
static void check(int index, uint64_t (*fn)(uint64_t *, uint64_t *, uint64_t)) {
    for (unsigned sample = 0; sample < 16; sample++) {
        uint64_t input = inputs[sample];
        for (unsigned alias = 0; alias < 2; alias++) {
            uint64_t left[32], right[32];
            for (unsigned i = 0; i < 32; i++) {
                left[i] = (uint64_t)(i+1)*UINT64_C(0x0102030405060708)^input;
                right[i] = ~left[i]^UINT64_C(0x96a5b4c3d2e1f087);
            }

            uint64_t *p = &left[2], *q = alias ? p : &right[2];
            uint64_t value = fn(p, q, input);

            printf("%d %u %u %016llx", index, sample, alias, (unsigned long long)value);
            for (unsigned i = 0; i < 32; i++) {
                printf(" %016llx", (unsigned long long)left[i]);
            }
            for (unsigned i = 0; i < 32; i++) {
                printf(" %016llx", (unsigned long long)right[i]);
            }
            putchar('\n');
        }
    }
}
int main(void) {
` + cCalls.String() + "return 0;\n}\n"
	return
}

func fixedLocalPointerChoiceRuntime(t *testing.T, execution x86FloatCompareExecution, execute bool) {
	t.Helper()
	goAMD64FramePrepareOwnedToolCache(t)
	assembly, declarations, original, driver := fixedLocalPointerChoiceRuntimeProgram(t, execution.triple)
	var want []string
	if execute {
		output := x86ScalarFloatIntegerOriginalOutput(t, execution, assembly, original)
		want = strings.Split(strings.TrimSpace(string(output)), "\n")
		if len(want) != 48*16*2 {
			t.Fatal("original Go pointer-choice runtime output inventory changed", len(want))
		}
	} else {
		x86COMICompileOriginalGo(t, map[string]string{
			"go.mod": "module pointerchoices\ngo 1.20\n", "main.go": original, "original_amd64.s": assembly,
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
					if !execute {
						execution.compileLLVM(t, "pointer-choices", input, driver, level)
						return
					}
					output := execution.compileAndRunLLVM(t, "pointer-choices", input, driver, level)
					got := strings.Split(strings.TrimSpace(string(output)), "\n")
					if len(got) != len(want) {
						t.Fatal("LLVM pointer-choice output inventory changed", len(got), len(want))
					}
					for index := range want {
						if got[index] != want[index] {
							t.Fatalf("pointer-choice kernel=%d sample=%d alias=%d: original=%s LLVM=%s",
								index/32, index/2%16, index%2, want[index], got[index])
						}
					}
				})
			}
		})
	t.Logf("48 complete functions, 16 input patterns, two pointer alias relations, return and both 256-byte buffers; execute=%v", execute)
}

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalPointerChoices(t *testing.T) {
	fixedLocalPointerChoiceRuntime(t, x86FloatCompareRuntimeTools(t, x86FloatCompareSSE), true)
}

func TestGoAMD64FixedLocalPointerChoiceRuntimeObjects(t *testing.T) {
	fixedLocalPointerChoiceRuntime(t, fixedLocalPackedCompileOnlyTools(t), false)
}
