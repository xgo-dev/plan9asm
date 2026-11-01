//go:build unix && go1.27

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func fixedLocalConstantArithmeticProgram(t *testing.T) (string, string, []string) {
	t.Helper()
	cases := fixedLocalConstantArithmeticCases()
	if len(cases) != 20 {
		t.Fatal("constant arithmetic runtime inventory changed", len(cases))
	}
	var assembly, declarations strings.Builder
	var expected []string
	for _, input := range []int{0, -1} {
		for _, row := range cases {
			name := fmt.Sprintf("Value%d", len(expected))
			// Exercise both successors of the same-value join independently.
			body := fmt.Sprintf("MOVQ $77,24(SP)\nMOVQ $%d,AX\n%s\nMOVQ (SP)(SI*8),AX", input, row.body)
			assembly.WriteString(fixedLocalConstantIndexFunction(name, body))
			fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
			expected = append(expected, "000000000000004d")
		}
	}
	return assembly.String(), declarations.String(), expected
}

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalConstantArithmetic(t *testing.T) {
	assembly, declarations, expected := fixedLocalConstantArithmeticProgram(t)
	fixedLocalConstantResultsRuntime(t, assembly, declarations, expected)
}

func TestGoAMD64FixedLocalConstantArithmeticObjects(t *testing.T) {
	assembly, declarations, expected := fixedLocalConstantArithmeticProgram(t)
	fixedLocalCompleteVectorObjects(t, assembly, declarations, len(expected))
}
