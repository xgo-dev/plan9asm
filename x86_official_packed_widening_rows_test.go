package plan9asm

import (
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86OfficialPackedWideningRowsInitializedThreeAPIsObjects(t *testing.T) {
	x86OfficialPackedRowsObjects(t, goasmrules.X86PackedWideningRows, 108, 288, 0)
}
