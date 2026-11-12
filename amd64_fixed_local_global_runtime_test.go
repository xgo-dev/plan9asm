//go:build unix && go1.27

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalMutableGlobal(t *testing.T) {
	execution := x86FloatCompareRuntimeTools(t, x86FloatCompareSSE)
	goAMD64FramePrepareOwnedToolCache(t)
	const original = `package main
import "fmt"
var Table [4]uint64
func Value(a uint64) uint64
func main() {
    for i := uint64(0); i < 17; i++ {
        for j := range Table { Table[j] = (i + uint64(j)) * 0x1020304050607081 }
        fmt.Printf("%016x\n", Value(i))
        Table[0] ^= ^uint64(0)
        fmt.Printf("%016x\n", Value(i))
    }
}
`
	want := strings.Split(strings.TrimSpace(string(x86ScalarFloatIntegerOriginalOutput(t, execution, fixedLocalGlobalAssembly, original))), "\n")
	if len(want) != 34 {
		t.Fatalf("original mutable Go variable produced %d rows, want 34", len(want))
	}
	prefix := ""
	if strings.Contains(execution.triple, "apple") {
		prefix = "_"
	}
	driver := runtimeCAsmLabelPreamble + fmt.Sprintf(`#include <stdint.h>
#include <stdio.h>
uint64_t table[4] __asm__(%s);
extern uint64_t value(uint64_t) __asm__(%s);
int main(void) {
    for (uint64_t i = 0; i < 17; i++) {
        for (unsigned j = 0; j < 4; j++) table[j] = (i + j) * UINT64_C(0x1020304050607081);
        printf("%%016llx\n", (unsigned long long)value(i));
        table[0] ^= UINT64_MAX;
        printf("%%016llx\n", (unsigned long long)value(i));
    }
    return 0;
}
`, runtimeCAsmLabel(prefix+"example.invalid/framefixture.Table"), runtimeCAsmLabel(prefix+"example.invalid/framefixture.Value"))
	pkg, request, _, options := fixedLocalTransportFixture(t, fixedLocalGlobalAssembly,
		fixedLocalGlobalDeclarations, runtime.GOOS+"/amd64", execution.triple)
	fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
		func(t *testing.T, ir string, err error) {
			if err != nil {
				t.Fatal(err)
			}
			fixedLocalGlobalCheckExternal(t, ir)
			for _, level := range []string{"-O0", "-O2"} {
				t.Run(level, func(t *testing.T) {
					input := ir
					if level == "-O2" {
						input = x86MulDivRoundOptimize(t, ir)
					}
					output := execution.compileAndRunLLVM(t, "mutable-global", input, driver, level)
					got := strings.Split(strings.TrimSpace(string(output)), "\n")
					if len(got) != len(want) {
						t.Fatalf("LLVM row count = %d, original = %d", len(got), len(want))
					}
					for index := range want {
						if got[index] != want[index] {
							t.Fatalf("mutable global row %d: original %s; LLVM %s", index, want[index], got[index])
						}
					}
				})
			}
		})
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		t.Log("original Go and LLVM amd64 execution via Rosetta, not native x86 hardware")
	}
}
