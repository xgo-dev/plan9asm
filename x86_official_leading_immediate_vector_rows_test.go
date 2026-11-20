package plan9asm

import (
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86OfficialLeadingImmediateVectorRowsInitializedThreeAPIsObjects(t *testing.T) {
	x86OfficialPackedRowsObjectsUsing(t, goasmrules.X86LeadingImmediateVectorRows, 66, 270, 0, x86OfficialFMA3Assembly)
}
