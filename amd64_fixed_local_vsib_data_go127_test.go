//go:build go1.27

package plan9asm

import (
	"strings"
	"testing"
)

func TestGoAMD64FixedLocalVSIBStackReadonlyIndices(t *testing.T) {
	row := fixedLocalVSIBOriginalStackFixtures()[0]
	row.op = "VPGATHERQQ X0, 16(SP)(X1*8), X2"
	row.setup = strings.Replace(row.setup, "VPXOR X1,X1,X1", "VMOVUPS indices<>(SB),X1", 1)
	const literals = "DATA indices<>+0(SB)/8,$-1\nDATA indices<>+8(SB)/8,$3\nGLOBL indices<>(SB),8,$16\n"
	fixedLocalVSIBStackObjects(t, literals, []fixedLocalVSIBFixture{row})
}
