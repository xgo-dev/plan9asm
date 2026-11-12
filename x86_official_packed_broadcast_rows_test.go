package plan9asm

import (
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86OfficialPackedBroadcastRowsInitializedThreeAPIsObjects(t *testing.T) {
	x86OfficialPackedRowsObjects(t, goasmrules.X86PackedBroadcastRows, 111, 234, 0)
}
