//go:build unix && go1.27

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func fixedLocalLogicalLiteralOracles(kernels []fixedLocalLogicalLiteralKernel, triple string) (string, string) {
	var goRows, declarations, cRows strings.Builder
	prefix := ""
	if strings.Contains(triple, "apple") {
		prefix = "_"
	}
	for _, kernel := range kernels {
		annihilate := 0
		if kernel.annihilate {
			annihilate = 1
		}
		fmt.Fprintf(&goRows, "{%s,%d,%d,%t},\n", kernel.name, kernel.row.width, kernel.row.mode, kernel.annihilate)
		fmt.Fprintf(&declarations, "extern void %s(const uint8_t *,uint8_t *) __asm__(%q);\n",
			kernel.name, prefix+"example.invalid/framefixture."+kernel.name)
		fmt.Fprintf(&cRows, "{%s,%d,%d,%d},\n", kernel.name, kernel.row.width, kernel.row.mode, annihilate)
	}
	original := `package framefixture

import "testing"

func TestOriginal(t *testing.T) {
    rows := []struct {
        call func(*byte, *byte)
        width, mode int
        annihilate bool
    }{
` + goRows.String() + `
    }
    count := 0
    for row, test := range rows {
        for sample := 0; sample < 256; sample++ {
            for alias := 0; alias < 2; alias++ {
                var input, output [96]byte
                for at := range input {
                    input[at] = byte(at*29 + sample)
                    output[at] = byte(at*7 + sample + 151)
                }
                before := input
                wantInput, wantOutput := input, output
                destination := &output[17]
                if alias != 0 {
                    destination = &input[17]
                }
                for at := 0; at < test.width; at++ {
                    selected := !test.annihilate && at >= 12 && at < 16
                    var first, second byte
                    if selected {
                        second = before[24+at-12]
                    }
                    switch test.mode {
                    case 0, 1:
                        if selected { first = 255 }
                    case 2:
                        if !selected { first = 255 }
                    case 3:
                        first, second = byte(at*13+7), before[24+at]
                    default:
                        t.Fatal("unknown operation")
                    }
                    var want byte
                    switch test.mode {
                    case 0: want = first & second
                    case 1: want = first & ^second
                    case 2: want = first | second
                    case 3: want = first ^ second
                    }
                    if alias != 0 {
                        wantInput[17+at] = want
                    } else {
                        wantOutput[17+at] = want
                    }
                }
                test.call(&input[24], destination)
                if input != wantInput || output != wantOutput {
                    t.Fatalf("row=%d sample=%d alias=%d input=%x/%x output=%x/%x", row, sample, alias,
                        input, wantInput, output, wantOutput)
                }
                count++
            }
        }
    }
    if count != len(rows)*256*2 { t.Fatal("incomplete source execution", count) }
}
`
	driver := `#include <stdint.h>
#include <stdio.h>
#include <string.h>
` + declarations.String() + `
static const struct {
    void (*call)(const uint8_t *, uint8_t *);
    unsigned width, mode, annihilate;
} cases[] = {
` + cRows.String() + `
};

int main(void) {
    unsigned count = 0;
    for (unsigned row = 0; row < sizeof(cases)/sizeof(cases[0]); row++) {
        for (unsigned sample = 0; sample < 256; sample++) {
            for (unsigned alias = 0; alias < 2; alias++) {
                uint8_t input[96], output[96], before[96], want_input[96], want_output[96];
                for (unsigned at = 0; at < sizeof(input); at++) {
                    input[at] = (uint8_t)(at*29 + sample);
                    output[at] = (uint8_t)(at*7 + sample + 151);
                }
                memcpy(before, input, sizeof(input));
                memcpy(want_input, input, sizeof(input));
                memcpy(want_output, output, sizeof(output));
                for (unsigned at = 0; at < cases[row].width; at++) {
                    unsigned selected = !cases[row].annihilate && at >= 12 && at < 16;
                    uint8_t first = 0, second = selected ? before[24+at-12] : 0, want;
                    switch (cases[row].mode) {
                    case 0: case 1: first = selected ? 255 : 0; break;
                    case 2: first = selected ? 0 : 255; break;
                    case 3: first = (uint8_t)(at*13+7); second = before[24+at]; break;
                    default: return 2;
                    }
                    switch (cases[row].mode) {
                    case 0: want = first & second; break;
                    case 1: want = first & (uint8_t)~second; break;
                    case 2: want = first | second; break;
                    case 3: want = first ^ second; break;
                    default: return 3;
                    }
                    if (alias) want_input[17+at] = want;
                    else want_output[17+at] = want;
                }
                cases[row].call(input+24, alias ? input+17 : output+17);
                if (memcmp(input, want_input, sizeof(input)) || memcmp(output, want_output, sizeof(output))) {
                    fprintf(stderr, "row=%u sample=%u alias=%u full buffer/canary mismatch\n", row, sample, alias);
                    return 1;
                }
                count++;
            }
        }
    }
    if (count != sizeof(cases)/sizeof(cases[0])*256*2) return 4;
    puts("logical literal values and complete canaries PASS");
    return 0;
}
`
	return original, driver
}

func fixedLocalLogicalLiteralRuntime(t *testing.T, execution x86FloatCompareExecution, execute bool) {
	t.Helper()
	goAMD64FramePrepareOwnedToolCache(t)
	kernels := fixedLocalLogicalLiteralKernels(t)
	for start := 0; start < len(kernels); start += 24 {
		end := start + 24
		if end > len(kernels) {
			end = len(kernels)
		}
		t.Run(fmt.Sprint(start/24), func(t *testing.T) {
			assembly, declarations := fixedLocalLogicalLiteralProgram(kernels[start:end])
			original, driver := fixedLocalLogicalLiteralOracles(kernels[start:end], execution.triple)
			fixedLocalPackedRunOriginal(t, execution, assembly, declarations, original, execute)
			pkg, request, _, options := fixedLocalTransportFixture(t, assembly, declarations,
				runtime.GOOS+"/amd64", execution.triple)
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
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
								execution.compileLLVM(t, "logical-literal-oracle", input, driver, level)
								return
							}
							output := execution.compileAndRunLLVM(t, "logical-literal-oracle", input, driver, level)
							if strings.TrimSpace(string(output)) != "logical literal values and complete canaries PASS" {
								t.Fatal("incomplete original byte oracle execution", string(output))
							}
						})
					}
				})
		})
	}
	t.Logf("45 original kernels, 256 samples, disjoint/overlapping inputs and outputs, both complete 96-byte buffers; execute=%t", execute)
}

func TestGoAMD64FixedLocalLogicalLiteralRuntimeObjects(t *testing.T) {
	fixedLocalLogicalLiteralRuntime(t, fixedLocalPackedCompileOnlyTools(t), false)
}
