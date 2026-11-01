package plan9asm

import (
	"fmt"
	"testing"
)

func TestARM64PoolAffineNegateAliases(t *testing.T) {
	type example struct {
		line   string
		value  arm64PoolAffine
		affine bool
	}
	var examples []example
	for _, opcode := range []string{"neg", "negs"} {
		for _, width := range []string{"x", "w"} {
			for _, shift := range []string{"lsl", "lsr", "asr"} {
				for _, amount := range []uint{0, 1, 30, 31, 63} {
					if width == "w" && amount > 31 {
						continue
					}
					line := fmt.Sprintf("%s %s1,%s2,%s #%d", opcode, width, width, shift, amount)
					affine := width == "x" && shift == "lsl" && amount <= 30
					var value arm64PoolAffine
					if affine {
						value.coefficient[2] = -(int64(1) << amount)
					}
					examples = append(examples, example{line, value, affine})
				}
			}
		}
		examples = append(examples, example{opcode + " x1,xzr", arm64PoolAffine{}, true})
	}
	var lines []string
	for _, test := range examples {
		lines = append(lines, test.line)
	}
	words := assembleARM64LLVMWords(t, lines, "")
	for at, test := range examples {
		destination, value, affine := arm64PoolAffineDefinition(words[at])
		if affine != test.affine || affine && (destination != 1 || value != test.value) {
			t.Errorf("%s: destination=%d value=%+v affine=%v, want %+v affine=%v",
				test.line, destination, value, affine, test.value, test.affine)
		}
	}
}
