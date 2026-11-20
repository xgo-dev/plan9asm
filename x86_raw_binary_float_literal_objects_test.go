package plan9asm

import (
	"fmt"
	"testing"
)

// Cover the complete memory-literal encoding directory independently of the
// old uninitialized format fixture: six packed/scalar binary operations and
// scalar square root, both refining precisions, VEX/EVEX widths and broadcast.
// The existing constructor keeps the original opcode, raw RET and exact pool.
func x86RawBinaryFloatInitializedLiteralCases(t *testing.T) []x86RawVectorLiteralCase {
	t.Helper()
	var rows []x86RawVectorLiteralCase
	for _, opcode := range []byte{0x51, 0x58, 0x59, 0x5c, 0x5d, 0x5e, 0x5f} {
		for pp := byte(0); pp < 4; pp++ {
			if opcode == 0x51 && pp < 2 {
				continue
			}
			for _, evex := range []bool{false, true} {
				widths := []int{16, 32}
				if evex {
					widths = append(widths, 64)
				}
				if pp >= 2 {
					widths = []int{16}
				}
				for _, width := range widths {
					broadcasts := []bool{false}
					if evex && pp < 2 {
						broadcasts = append(broadcasts, true)
					}
					for _, broadcast := range broadcasts {
						rows = append(rows, x86RawVectorLiteralCase{
							name: fmt.Sprintf("Literal_%x_%d_%t_%d_%t", opcode, pp, evex, width, broadcast),
							code: x86RawBinaryFloatLiteral(opcode, pp, evex, width, broadcast),
						})
					}
				}
			}
		}
	}
	if len(rows) != 124 {
		t.Fatal("incomplete binary/scalar floating RIP directory", len(rows))
	}
	return rows
}

func TestX86RawBinaryFloatInitializedLiteralLinuxObjects(t *testing.T) {
	x86RawVectorLiteralObjects(t, "x86_64-unknown-linux-gnu", x86RawBinaryFloatInitializedLiteralCases(t))
}

func TestX86RawBinaryFloatInitializedLiteralDarwinObjects(t *testing.T) {
	x86RawVectorLiteralObjects(t, "x86_64-apple-darwin", x86RawBinaryFloatInitializedLiteralCases(t))
}

func TestX86RawBinaryFloatInitializedLiteralWindowsObjects(t *testing.T) {
	x86RawVectorLiteralObjects(t, "x86_64-pc-windows-msvc", x86RawBinaryFloatInitializedLiteralCases(t))
}
