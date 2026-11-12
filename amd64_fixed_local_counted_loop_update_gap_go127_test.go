//go:build go1.27

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func fixedLocalCountedLoopUpdateGapProgram(t *testing.T) (string, string, int) {
	t.Helper()
	var assembly, declarations strings.Builder
	count := 0
	for _, row := range fixedLocalCountedLoopUpdateGapCases() {
		if !strings.HasPrefix(row.name, "SI/") ||
			!strings.HasSuffix(row.name, "/GP and flags") && !strings.HasSuffix(row.name, "/two vector moves") {
			continue
		}
		// The scratch GP in the gap changes AX. Keep the input separately
		// and make every initialized slot equal input+2 modulo the word size.
		body := "MOVQ a+0(FP),R8\n" + strings.Replace(row.body,
			"MOVQ $7,16(SP)(SI*8)", "MOVQ R8,16(SP)(SI*8)\nADDQ $2,16(SP)(SI*8)", 1)
		_, _, source := fixedLocalCountedLoopFixture(t, body)
		name := fmt.Sprintf("Value%d", count)
		assembly.WriteString(strings.Replace(source, "·Value", "·"+name, 1))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
		count++
	}
	if count != 8 {
		t.Fatal("four counter updates by GP/vector gap inventory changed", count)
	}
	return assembly.String(), declarations.String(), count
}

func TestGoAMD64FixedLocalCountedLoopUpdateGapObjects(t *testing.T) {
	assembly, declarations, count := fixedLocalCountedLoopUpdateGapProgram(t)
	fixedLocalCountedLoopObjects(t, assembly, declarations, count)
}
