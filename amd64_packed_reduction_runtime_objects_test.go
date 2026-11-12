//go:build unix

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func x86PackedReductionNativeFixtureObjects(t *testing.T, faults bool) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	rows := x86PackedReductionNativeRows(faults)
	limit := x86PackedReductionValueCapture
	if faults {
		limit = x86PackedReductionFaultCapture
	}
	consumed := 0
	for start := 0; start < len(rows); start += limit {
		end := start + limit
		if end > len(rows) {
			end = len(rows)
		}
		t.Run(fmt.Sprintf("batch-%04d", start), func(t *testing.T) {
			current := rows[start:end]
			var original [][]byte
			if faults {
				original = x86PackedReductionFaultOriginalBytes(t, current)
			}
			fixture := func(rows []x86PackedReductionRuntimeRow) (string, string) {
				if faults {
					assembly, declarations, _ := x86PackedReductionFaultFixture(rows, original)
					return assembly, declarations
				}
				assembly, declarations, _, _ := x86PackedReductionRuntimeFixture(rows)
				return assembly, declarations
			}
			assembly, declarations := fixture(current)
			raw := x86PackedReductionRuntimeRawRows(t, current, faults)
			rawRows := append([]x86PackedReductionRuntimeRow(nil), current...)
			for index := range rawRows {
				rawRows[index].instruction = raw[index]
			}
			rawAssembly, _ := fixture(rawRows)
			for _, spelling := range []struct{ name, source string }{{"named", assembly}, {"raw", rawAssembly}} {
				t.Run(spelling.name, func(t *testing.T) {
					x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", spelling.source)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, spelling.source, declarations, "amd64", "x86_64-unknown-linux-gnu", api)
							if err != nil {
								t.Fatal("initialized native runtime fixture rejected before execution", err)
							}
							optimized := x86DwordProductIROptimize(t, ir)
							for _, pipeline := range []struct{ name, ir, backend string }{
								{"backend_O0", ir, "-O0"}, {"backend_O2", ir, "-O2"}, {"IR_O2_backend_O2", optimized, "-O2"},
							} {
								t.Run(pipeline.name, func(t *testing.T) {
									for index, row := range current {
										name := fmt.Sprintf("reduction%d", index)
										if faults {
											name = fmt.Sprintf("reductionfault%d", index)
										}
										_, body, found := strings.Cut(pipeline.ir, "define void @"+name+"(")
										body, _, ended := strings.Cut(body, "\n}")
										if !found || !ended || strings.Count(body, `asm sideeffect "`+row.oracle.mnemonic+` `) != 1 ||
											!strings.Contains(body, "~{fpsr}") || !strings.Contains(body, "~{memory}") {
											t.Fatal("actual runtime fixture lost the original whole arithmetic/exception effect", row.instruction)
										}
									}
									x86PackedStringCompileObject(t, llc, "x86_64-unknown-linux-gnu", pipeline.ir, pipeline.backend)
								})
							}
						})
					}
				})
			}
			consumed += len(current)
		})
	}
	if consumed != len(rows) {
		t.Fatal("native runtime object partition lost initialized rows", consumed, len(rows))
	}
	t.Logf("all%d actual native runtime kernels have initialized Go/public3API/3pipeline objects; this is not native execution", consumed)
}

func TestX86PackedReductionNativeValueFixtureObjects(t *testing.T) {
	x86PackedReductionNativeFixtureObjects(t, false)
}

func TestX86PackedReductionNativeFaultFixtureObjects(t *testing.T) {
	x86PackedReductionNativeFixtureObjects(t, true)
}
