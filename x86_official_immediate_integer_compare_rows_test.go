package plan9asm

import (
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86OfficialImmediateIntegerCompareRowsInitializedThreeAPIsObjects(t *testing.T) {
	x86OfficialPackedRowsObjects(t, goasmrules.X86ImmediateIntegerCompareRows, 48, 240, 0)
}
