//go:build go1.27

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Actual Go archives/ABI0 objects are checked by the source owner. This
// independent C callee executes the translated logical call on the host;
// it does not claim original native AMD64 or Go runtime execution.
func TestGoAMD64FrameOrdinaryCallPortableValues(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	execution := x86ScalarCountHostExecution(t)
	pkg, request, _, options := ordinaryGoFrameCallFixture(t,
		ordinaryGoFrameCallDeclarations, ordinaryGoFrameCallAssembly)
	prefix := ""
	if strings.Contains(execution.triple, "apple") {
		prefix = "_"
	}
	driver := fmt.Sprintf(`#include <stdint.h>
#include <stdio.h>
static unsigned calls;
uint64_t callee(uint64_t) __asm__(%q);
uint64_t callee(uint64_t a) { ++calls; return (a ^ UINT64_C(11)) + UINT64_C(17); }
extern uint64_t value(uint64_t) __asm__(%q);
int main(void) {
    const uint64_t edges[] = {0, 1, 10, 11, 12, UINT64_MAX, UINT64_C(0x8000000000000000), UINT64_C(0x7fffffffffffffff)};
    uint64_t random = UINT64_C(0x893701ab2468cdfe);
    for (unsigned i = 0; i < 264; ++i) {
        random ^= random << 13; random ^= random >> 7; random ^= random << 17;
        uint64_t input = i < 8 ? edges[i] : random;
        uint64_t expected = (input ^ UINT64_C(11)) + UINT64_C(17) + UINT64_C(37);
        uint64_t got = value(input);
        if (got != expected || calls != i + 1) {
            fprintf(stderr, "ordinary call input=%%llu got=%%llu expected=%%llu calls=%%u\n",
                (unsigned long long)input, (unsigned long long)got, (unsigned long long)expected, calls);
            return 1;
        }
    }
    return 0;
}
`, prefix+pkg.Path+".Callee", prefix+pkg.Path+".Value")
	fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
		func(t *testing.T, ir string, err error) {
			if err != nil {
				t.Fatal(err)
			}
			for _, optimized := range []bool{false, true} {
				text := ir
				if optimized {
					text = x86MulDivRoundOptimize(t, text)
				}
				for _, level := range []string{"-O0", "-O2"} {
					t.Run(fmt.Sprintf("IR-O2=%t/backend%s", optimized, level), func(t *testing.T) {
						execution.compileAndRunLLVM(t, "ordinary-call", text, driver, level)
					})
				}
			}
		})
}
