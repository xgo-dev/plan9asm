package plan9asm

import (
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86OfficialSingleSourceNarrowingRowsThreeAPIsObjectsAndTerminalFaults(t *testing.T) {
	cases := x86OfficialPackedRowsObjectsInspect(t, goasmrules.X86SingleSourceNarrowingRows, 108, 324, 0,
		x86OfficialMoveAssembly, x86OfficialMoveInspectFaults)
	faults := 0
	for _, fixture := range cases {
		if fixture.witness.Zeroing && fixture.witness.Destination == "(AX)" {
			faults++
		}
	}
	if faults != 54 || len(cases)-faults != 270 {
		t.Fatal("ordinary initialized narrowing and encoded terminal #UD were conflated", len(cases), faults)
	}
}
