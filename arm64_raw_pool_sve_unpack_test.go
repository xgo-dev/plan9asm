package plan9asm

import (
	"fmt"
	"testing"
)

func TestARM64RawPoolSVEUnpackEffects(t *testing.T) {
	var lines []string
	for _, op := range []string{"sunpklo", "sunpkhi", "uunpklo", "uunpkhi"} {
		for _, widths := range [][2]string{{"h", "b"}, {"s", "h"}, {"d", "s"}} {
			for _, source := range []int{0, 9, 31} {
				lines = append(lines, fmt.Sprintf("%s z9.%s,z%d.%s", op, widths[0], source, widths[1]))
			}
		}
	}
	for index, word := range assembleARM64LLVMWords(t, lines, "+sve") {
		if !arm64RawPoolSVEPreservesNZCV(word) {
			t.Errorf("%s: unpack unexpectedly clobbers NZCV", lines[index])
		}
		if writes, known := arm64RawPoolGPWrites(word); !known || writes != 0 {
			t.Errorf("%s: GP effects=%#x/%v, want no GP writes", lines[index], writes, known)
		}
		if !arm64RawPoolSVEIgnoresAddress(word, 9) {
			t.Errorf("%s: vector register was mistaken for an address use", lines[index])
		}
		// Size zero is reserved, even though the register fields are valid.
		if arm64RawPoolIndependentSVE(word&^(3<<22)) || arm64RawPoolSVEPreservesNZCV(word&^(3<<22)) {
			t.Errorf("%s: reserved byte destination acquired a safe effect", lines[index])
		}
	}
}
