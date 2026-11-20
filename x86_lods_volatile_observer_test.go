package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// Output stores can retain the native MOV's volatile qualifier after inlining.
// Classify every complete cell and keep all value, address and effect checks.
func TestX86LODSZeroStoreObserverVolatileAndLineEndingForms(t *testing.T) {
	observations := 0
	for _, arch := range []string{"386", "amd64"} {
		word := 8
		if arch == "386" {
			word = 4
		}
		bits := 8 * word
		for _, row := range x86LODSStateCases(arch) {
			if row.prefix == "" || row.count != 0 {
				continue
			}
			base := x86LODSZeroStoreTemplate(row)
			expected := x86LODSStateExpected(row)
			mutations := map[string]string{
				"wrong-width": strings.Replace(base, fmt.Sprintf("store i%d ", bits), "store i8 ", 1),
				"missing-CX": strings.Replace(base,
					fmt.Sprintf("store i%d 0, ptr %%ptr1, align %d\n", bits, word), "", 1),
				"foreign-store":   base + fmt.Sprintf("store i%d 0, ptr %%foreign, align %d\n", bits, word),
				"duplicate-store": base + fmt.Sprintf("store i%d 0, ptr %%out, align %d\n", bits, word),
				"unknown-call":    base + "call void @unknown()\n",
				"atomic-store":    strings.Replace(base, "store i", "store atomic i", 1),
				"double-volatile": strings.Replace(base, "store i", "store volatile volatile i", 1),
			}
			values := []string{strconv.FormatUint(expected.ax, 10), "%si", "0",
				strconv.FormatUint(expected.flags, 10)}
			for index, value := range values {
				mutations[fmt.Sprintf("cell%d-value", index)] = strings.Replace(base,
					fmt.Sprintf("store i%d %s,", bits, value), fmt.Sprintf("store i%d 7,", bits), 1)
			}
			for _, qualifier := range []string{"ordinary", "volatile"} {
				for _, ending := range []string{"LF", "CRLF"} {
					observations++
					t.Run(arch+"/"+row.name+"/"+qualifier+"/"+ending, func(t *testing.T) {
						format := func(body string) string {
							lines := strings.Split(body, "\n")
							for index, line := range lines {
								if qualifier == "volatile" && strings.HasPrefix(line, "store i") &&
									!strings.Contains(line, "ptr %flags_slot,") {
									lines[index] = strings.Replace(line, "store i", "store volatile i", 1)
								}
							}
							separator := "\n"
							if ending == "CRLF" {
								separator = "\r\n"
							}
							return strings.Join(lines, separator)
						}
						body := format(base)
						if err := x86LODSCheckZeroOutputStores(body, row); err != nil {
							t.Error("complete qualified output stores were rejected", err)
						}
						for name, changed := range mutations {
							if changed == base || x86LODSCheckZeroOutputStores(format(changed), row) == nil {
								t.Error("qualified observer accepted mutation", name)
							}
						}
					})
				}
			}
		}
	}
	if observations != 112 {
		t.Fatal("complete qualifier and line-ending matrix changed", observations)
	}
}
