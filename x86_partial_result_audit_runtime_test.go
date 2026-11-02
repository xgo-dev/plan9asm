package plan9asm

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestX86OrdinaryPartialResultsPortableCallerValues(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang required")
	}
	arch := "amd64"
	if strconv.IntSize == 32 {
		arch = "386"
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	const driver = `#include <stdint.h>
#include <stdio.h>
extern uint32_t ObservePartial(uint32_t);
int main(void) {
    const uint32_t input[] = {0, 1, 2, UINT32_MAX};
    const uint32_t expected[] = {99, 42, 42, 42};
    for (unsigned i = 0; i < 4; ++i) {
        uint32_t got = ObservePartial(input[i]);
        if (got != expected[i]) {
            fprintf(stderr, "partial result row=%u got=%u want=%u\n", i, got, expected[i]);
            return 1;
        }
    }
    return 0;
}
`
	for _, boolFirst := range []bool{false, true} {
		for _, byteOffset := range []int{-1, 0, 1} {
			name := fmt.Sprintf("bool-first=%t", boolFirst)
			if byteOffset >= 0 {
				name = fmt.Sprintf("partial-byte=%d/bool-first=%t", byteOffset, boolFirst)
			}
			t.Run(name, func(t *testing.T) {
				declaration, source, sig, _ := x86PartialResultFixture(t, arch, "uint32", "MOVL", boolFirst)
				valueIndex, boolIndex := 0, 1
				if boolFirst {
					valueIndex, boolIndex = 1, 0
				}
				// Only the false branch observes n. The Go source fixture and
				// independent C values do not require an unwritten success value.
				caller := fmt.Sprintf(`
define i32 @ObservePartial(i32 %%input) {
entry:
  %%pair = call %s @Value(i32 %%input)
  %%ok = extractvalue %s %%pair, %d
  br i1 %%ok, label %%success, label %%failure
failure:
  %%n = extractvalue %s %%pair, %d
  ret i32 %%n
success:
  ret i32 99
}
`, sig.Ret, sig.Ret, boolIndex, sig.Ret, valueIndex)
				cSource := driver
				if byteOffset >= 0 {
					// The caller observes a written byte while leaving every
					// unwritten byte unobserved, including an interior-byte store.
					body := fmt.Sprintf("MOVB $7,n+%d(FP)\nMOVB $1,ok+%d(FP)\nRET",
						sig.Frame.Results[valueIndex].Offset+int64(byteOffset), sig.Frame.Results[boolIndex].Offset)
					_, _, _, source = x86ResultInitializationFixture(t, arch, declaration, body)
					caller = fmt.Sprintf(`
define i32 @ObservePartial(i32 %%input) {
entry:
  %%pair = call %s @Value(i32 %%input)
  %%n = extractvalue %s %%pair, %d
  %%shifted = lshr i32 %%n, %d
  %%byte = and i32 %%shifted, 255
  ret i32 %%byte
}
`, sig.Ret, sig.Ret, valueIndex, byteOffset*8)
					cSource = strings.Replace(driver, "{99, 42, 42, 42}", "{7, 7, 7, 7}", 1)
				}
				goAssemblerOracleOutput(t, arch, source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
						if err != nil {
							t.Fatal(err)
						}
						ir += caller
						for _, optimized := range []bool{false, true} {
							t.Run(fmt.Sprintf("IR-O2=%t", optimized), func(t *testing.T) {
								text := ir
								if optimized {
									text = x86DwordProductIROptimize(t, ir)
								}
								for _, level := range []int{0, 2} {
									t.Run(fmt.Sprintf("backend-O%d", level), func(t *testing.T) {
										compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "partial-result-caller", triple, text, cSource, nil, level)
									})
								}
							})
						}
					})
				}
			})
		}
	}
}
