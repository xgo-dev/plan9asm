package plan9asm

import (
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86OfficialPackedImmediateShuffleRowsInitializedThreeAPIsObjects(t *testing.T) {
	x86OfficialPackedRowsObjectsUsing(t, goasmrules.X86PackedImmediateShuffleRows, 34, 95, 0, x86OfficialAbsAssembly)
}
