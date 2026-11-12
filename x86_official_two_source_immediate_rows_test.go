package plan9asm

import (
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86OfficialTwoSourceImmediateShuffleRowsInitializedThreeAPIsObjects(t *testing.T) {
	x86OfficialPackedRowsObjects(t, goasmrules.X86TwoSourceImmediateShuffleRows, 27, 90, 0)
}
