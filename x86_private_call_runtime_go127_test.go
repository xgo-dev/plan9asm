//go:build unix && go1.27

package plan9asm

import (
	"fmt"
	"math/bits"
	"strings"
	"testing"
)

// Reuse the complete original-Go/LLVM three-API O0/O2 owner. The only test
// adaptation fixes Value's second input to seven; helper bodies are unchanged.
func TestCrossLinuxRuntimeMatrixX86PrivateCallContinuations(t *testing.T) {
	cases := x86PrivateCallCases()
	if len(cases) != 11 {
		t.Fatal("complete ordinary private-call runtime inventory changed", len(cases))
	}
	assembly, declarations := x86PrivateCallWholeSource("amd64")
	assembly = strings.NewReplacer("$0-24", "$0-16", "MOVQ b+8(FP),BX", "MOVQ $7,BX",
		"ret+16(FP)", "ret+8(FP)").Replace(assembly)
	declarations = strings.ReplaceAll(declarations, "(a,b uint64)", "(a uint64)")
	inputs := []uint64{0, 1, 6, 7, 8, 0xffffffff, 0x100000000, ^uint64(0)}
	expected := make([][]string, len(inputs))
	for index, input := range inputs {
		for _, row := range cases {
			var result uint64
			switch row.name {
			case "two_calls":
				result = bits.RotateLeft64(input+7, 1) + 3
			case "incoming_flags", "nested_incoming_flags", "outgoing_flags":
				if input < 7 {
					result = 1
				}
			case "vector_result":
				result = uint64(uint32(input)) + 7
			case "nested_return", "nested_noframe_tail":
				result = input + 8
			case "called_leaf_tail":
				result = input + 7
			case "two_returns":
				result = input + 1
				if input < 7 {
					result = input - 1
				}
			case "two_call_flags":
				if input >= 7 {
					result = 1
				}
			case "two_call_vectors":
				result = uint64(uint32(input)) + 7
			default:
				t.Fatal("missing independent private-call oracle", row.name)
			}
			expected[index] = append(expected[index], fmt.Sprintf("%016x", result))
		}
	}
	fixedLocalResultsRuntime(t, assembly, declarations, inputs, expected)
}
