//go:build unix && go1.27

package plan9asm

import (
	"encoding/binary"
	"fmt"
	"testing"
)

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalReadonlyRange(t *testing.T) {
	assembly, declarations, cases := fixedLocalReadonlyRangeProgram(t)
	inputs := []uint64{0, 1, 2, 14, 15, 16, 17, 31}
	var data [240]byte
	for index := range data {
		data[index] = byte(index + 1)
	}
	var expected [][]string
	for _, input := range inputs {
		var values []string
		for _, row := range cases {
			index, stride := input, uint64(16)
			switch row.name {
			case "generic loop before bound":
				index %= 16
			case "scale/1":
				stride = 1
			case "scale/2":
				stride = 2
			case "scale/4":
				stride = 4
			case "scale/8":
				stride = 8
			}
			value := input // Every rejected boundary preserves the original AX.
			if index > 0 && index < 16 {
				value = binary.LittleEndian.Uint64(data[(index-1)*stride:])
			}
			values = append(values, fmt.Sprintf("%016x", value))
		}
		expected = append(expected, values)
	}
	fixedLocalResultsRuntime(t, assembly, declarations, inputs, expected)
}
