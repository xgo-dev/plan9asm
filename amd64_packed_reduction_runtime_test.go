//go:build unix

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func x86PackedReductionNativeValues(t *testing.T, owner int) {
	t.Helper()
	if owner < 0 || owner >= x86PackedReductionNativeOwners {
		t.Fatal("invalid complete native reduction value owner", owner)
	}
	execution := x86PackedReductionNativeTools(t)
	rows := x86PackedReductionNativeRows(false)
	if len(rows) != 258 {
		t.Fatal("complete native reduction value denominator changed", len(rows))
	}
	consumed := 0
	for batch, start := 0, 0; start < len(rows); batch, start = batch+1, start+x86PackedReductionValueCapture {
		if batch%x86PackedReductionNativeOwners != owner {
			continue
		}
		end := start + x86PackedReductionValueCapture
		if end > len(rows) {
			end = len(rows)
		}
		t.Run(fmt.Sprintf("batch-%04d", start), func(t *testing.T) {
			current := rows[start:end]
			assembly, declarations, original, driver := x86PackedReductionRuntimeFixture(current)
			var want []byte
			t.Run("original_go_named", func(t *testing.T) {
				want = x86ScalarFloatIntegerOriginalOutput(t, execution, assembly, original)
				if strings.Count(string(want), "\n") != len(current) {
					t.Fatal("incomplete original named Go reduction execution receipts")
				}
			})
			raw := x86PackedReductionRuntimeRawRows(t, current, false)
			rawRows := append([]x86PackedReductionRuntimeRow(nil), current...)
			for index := range rawRows {
				rawRows[index].instruction = raw[index]
			}
			rawAssembly, _, rawOriginal, _ := x86PackedReductionRuntimeFixture(rawRows)
			t.Run("original_go_raw", func(t *testing.T) {
				got := x86ScalarFloatIntegerOriginalOutput(t, execution, rawAssembly, rawOriginal)
				if string(got) != string(want) || len(want) == 0 {
					t.Fatal("original named/raw Go reduction execution differs or lost receipts")
				}
			})
			if len(want) == 0 {
				t.Fatal("missing actual original Go reduction execution")
			}
			for _, spelling := range []struct{ name, source string }{{"named", assembly}, {"raw", rawAssembly}} {
				t.Run(spelling.name, func(t *testing.T) {
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, spelling.source, declarations, "amd64", execution.triple, api)
							if err != nil {
								t.Fatal("initialized native reduction value source rejected", err)
							}
							x86PackedReductionNativePipelines(t, execution, ir, driver, want)
						})
					}
				})
			}
			consumed += len(current)
		})
	}
	if consumed == 0 {
		t.Fatal("empty complete native reduction value owner")
	}
	t.Logf("%d/258 actual named/raw Go kernels, full physical Y32 aliases/FLAGS/MXCSR,3 APIs and3 LLVM execution paths", consumed)
}
