package plan9asm

import (
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86OfficialPackedNumericConversionRowsInitializedThreeAPIsObjects(t *testing.T) {
	x86OfficialPackedRowsObjects(t, goasmrules.X86PackedNumericConversionRows, 162, 876, 0)
}
